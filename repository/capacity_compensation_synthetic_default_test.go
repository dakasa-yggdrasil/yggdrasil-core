//go:build !recoveryfixture && !nativequalification

package repository

import "testing"

// Repository-only synthetic member and readback facts are not physical qualification.
func syntheticCompensationIfEnabled(t *testing.T, protected, lost bool) bool {
	selected := "unprotected_failed_create"
	if protected {
		selected = "protected_failed_create_without_serving_membership"
	}
	if lost {
		selected = "lost_create_reply_uses_separate_native_readback"
	}
	if lost && protected {
		selected = "protected_lost_create_reply"
	}
	passed := runSyntheticRepositoryGate(t, "TestCapacityMutationCompensationPostgres", selected)
	if !protected && !lost {
		t.Run("global_slot_precedes_child_row_during_foreign_issue", func(t *testing.T) {
			// The child census confirms the actual nested test ran and passed.
			if !passed {
				t.Fatal("child lock-order test not confirmed")
			}
		})
	}
	return true
}

// The below-floor original node owns a distinct signed synthetic test process.
func syntheticFailedFloorIfEnabled(t *testing.T) bool {
	runSyntheticRepositoryGate(t, "TestSyntheticFailedFloorRecoveryPostgres", "")
	return true
}
