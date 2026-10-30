//go:build linux && nativequalification

package capacitynativeqemu

import (
	"context"
	"crypto/ed25519"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
)

func TestSourceFailureCleanupPreparationStages(t *testing.T) {
	workflow := uuid.New()
	store := repository.CapacityStore{WorkflowID: workflow}
	policy := model.Manifest{Metadata: model.ManifestMetadata{Namespace: "qualification"}}
	pre := model.CapacityGuestOriginalProvisioningPreregistration{Slot: 2, WorkflowID: workflow.String(), CoreSourceCommit: capacity.CurrentGuestCoreSource()}
	key := make(ed25519.PrivateKey, ed25519.PrivateKeySize)
	for _, tc := range []struct {
		name, nativeCase, want string

		slot int
	}{
		{"input", "source_live_failed_floor_recovery", "prepare_input", 1},
		{"foreign_case", "other", "prepare_input", 2},
		{"native_owners_missing", "source_live_failed_floor_recovery", "prepare_native", 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &Realm{Request: SourceRequest{NativeCase: tc.nativeCase}}
			candidate := pre
			candidate.Slot = tc.slot
			stage := "unknown"
			_, _, observed := r.PrepareSourceFailureCleanupDiagnostic(context.Background(), store, policy, candidate, "", "", key, &stage)
			_, _, original := r.PrepareSourceFailureCleanup(context.Background(), store, policy, candidate, "", "", key)
			if observed != ErrOriginalUnknown || original != observed || stage != tc.want {
				t.Fatalf("diagnostic changed refusal or stage: %q", stage)
			}
		})
	}
}
