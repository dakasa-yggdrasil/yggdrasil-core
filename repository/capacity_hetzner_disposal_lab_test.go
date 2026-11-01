package repository

import "testing"

// Explicitly exercise the existing source-local helpers. The storage rows are
// declared synthetic: no signed Guest quiescence or provider absence follows.
func TestLABFailedInstalledDisposalExistingStorage(t *testing.T) {
	t.Run("boundaries", testFailedInstalledDisposalBoundaries)
	t.Run("postgres_lineage_and_rollback", testFailedInstalledDisposalPostgres)
}
