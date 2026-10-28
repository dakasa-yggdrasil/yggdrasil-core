//go:build !recoveryfixture && !nativequalification

package repository

import "testing"

// Use the reviewed synthetic repository fixture only for accepted cases. Lost
// replies continue through the original case until their own evidence is ready.
func syntheticCompensationIfEnabled(t *testing.T, protected, lost bool) bool {
	if lost {
		return false
	}
	selected := "unprotected_failed_create"
	if protected {
		selected = "protected_failed_create_without_serving_membership"
	}
	passed := runSyntheticRepositoryGate(t, "TestCapacityMutationCompensationPostgres", selected)
	if !protected {
		t.Run("global_slot_precedes_child_row_during_foreign_issue", func(t *testing.T) {
			// The child census confirms the actual nested test ran and passed.
			if !passed {
				t.Fatal("child lock-order test not confirmed")
			}
		})
	}
	return true
}
