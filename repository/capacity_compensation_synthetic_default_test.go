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
	runSyntheticRepositoryGate(t, "TestCapacityMutationCompensationPostgres", selected)
	return true
}
