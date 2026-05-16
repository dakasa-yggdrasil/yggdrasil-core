package repository

import "testing"

func TestSyncCanonEventTypeConstants(t *testing.T) {
	cases := []struct {
		name string
		got  string
		want string
	}{
		{"contract_mismatch_detected", EventTypeRuntimeStateContractMismatchDetected, "runtime_state.contract_mismatch_detected"},
		{"integration_type_synced", EventTypeIntegrationTypeSynced, "integration_type.synced"},
		{"integration_type_sync_no_op", EventTypeIntegrationTypeSyncNoOp, "integration_type.sync_no_op"},
		{"integration_type_sync_skipped", EventTypeIntegrationTypeSyncSkipped, "integration_type.sync_skipped"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.got != c.want {
				t.Fatalf("constant value mismatch: got %q want %q", c.got, c.want)
			}
		})
	}
}

func TestSyncEventTypesAreNotCanonLifecycle(t *testing.T) {
	// Sync events are infrastructure, not lifecycle. Materializer must skip them.
	for _, e := range []string{
		EventTypeRuntimeStateContractMismatchDetected,
		EventTypeIntegrationTypeSynced,
		EventTypeIntegrationTypeSyncNoOp,
		EventTypeIntegrationTypeSyncSkipped,
	} {
		if IsCanonLifecycleEvent(e) {
			t.Fatalf("event %q must NOT be in CanonLifecycleEventTypes (infrastructure event)", e)
		}
	}
}
