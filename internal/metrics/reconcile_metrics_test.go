package metrics

import "testing"

// Audit 2026-05-27 G4: reconcile_fail_count metric must be present, label
// cardinality must stay bounded to the closed-set kinds, and unknown
// kinds must be no-ops.

func TestIncReconcileFailure_HappyPath(t *testing.T) {
	ResetForTest()
	IncReconcileFailure(ReconcileKindPermissionCatalog)
	IncReconcileFailure(ReconcileKindPermissionCatalog)
	IncReconcileFailure(ReconcileKindSecretMaterialize)

	snap := ReconcileFailuresSnapshot()
	if snap[ReconcileKindPermissionCatalog] != 2 {
		t.Errorf("permission_catalog expected 2, got %d", snap[ReconcileKindPermissionCatalog])
	}
	if snap[ReconcileKindSecretMaterialize] != 1 {
		t.Errorf("secret_materialize expected 1, got %d", snap[ReconcileKindSecretMaterialize])
	}
	if snap[ReconcileKindManifestApply] != 0 {
		t.Errorf("manifest_apply expected 0 (never bumped), got %d", snap[ReconcileKindManifestApply])
	}
}

func TestIncReconcileFailure_UnknownKindDropped(t *testing.T) {
	ResetForTest()
	IncReconcileFailure("nonexistent_kind")
	IncReconcileFailure("")

	snap := ReconcileFailuresSnapshot()
	total := uint64(0)
	for _, v := range snap {
		total += v
	}
	if total != 0 {
		t.Fatalf("unknown kinds must be dropped; got total=%d", total)
	}
}

func TestReconcileFailuresSnapshot_AllKindsPresent(t *testing.T) {
	ResetForTest()
	snap := ReconcileFailuresSnapshot()
	// Closed-set: every known kind must be present (zero-padded) so the
	// /metrics scrape emits stable rows.
	for _, kind := range []string{
		ReconcileKindPermissionCatalog,
		ReconcileKindSecretMaterialize,
		ReconcileKindManifestApply,
	} {
		if _, ok := snap[kind]; !ok {
			t.Errorf("snapshot missing closed-set kind %q (must be zero-padded)", kind)
		}
	}
}

func TestResetForTest_ClearsReconcileFailures(t *testing.T) {
	IncReconcileFailure(ReconcileKindPermissionCatalog)
	IncReconcileFailure(ReconcileKindSecretMaterialize)

	ResetForTest()
	snap := ReconcileFailuresSnapshot()
	for k, v := range snap {
		if v != 0 {
			t.Errorf("ResetForTest must zero all counters; %s=%d", k, v)
		}
	}
}
