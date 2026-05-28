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

func TestExternalIdentityCanonEventConstants(t *testing.T) {
	cases := []struct {
		got  string
		want string
	}{
		{EventTypeExternalIdentityLinked, "collaborator_external_identity.linked"},
		{EventTypeExternalIdentityUnlinked, "collaborator_external_identity.unlinked"},
		{EventTypeExternalIdentityDriftDetected, "collaborator_external_identity.drift_detected"},
		{EventTypeExternalIdentityUnknownExternal, "collaborator_external_identity.unknown_external"},
		{EventTypeExternalIdentityPurged, "collaborator_external_identity.purged"},
		{EventTypeExternalIdentityConflictDetected, "collaborator_external_identity.conflict_detected"},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Fatalf("constant mismatch: got %q want %q", c.got, c.want)
		}
	}
}

func TestExternalIdentityEventsAreNotCanonLifecycle(t *testing.T) {
	for _, e := range []string{
		EventTypeExternalIdentityLinked,
		EventTypeExternalIdentityUnlinked,
		EventTypeExternalIdentityDriftDetected,
		EventTypeExternalIdentityUnknownExternal,
		EventTypeExternalIdentityPurged,
		EventTypeExternalIdentityConflictDetected,
	} {
		if IsCanonLifecycleEvent(e) {
			t.Fatalf("event %q must NOT be in CanonLifecycleEventTypes (infrastructure event)", e)
		}
	}
}

func TestTeamGrantEventConstants(t *testing.T) {
	cases := []struct {
		got  string
		want string
	}{
		{EventTypeTeamGrantAdded, "team_grant.added"},
		{EventTypeTeamGrantRevoked, "team_grant.revoked"},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Fatalf("constant mismatch: got %q want %q", c.got, c.want)
		}
	}
}

func TestTeamGrantEventsAreCanonLifecycle(t *testing.T) {
	for _, e := range []string{
		EventTypeTeamGrantAdded,
		EventTypeTeamGrantRevoked,
	} {
		if !IsCanonLifecycleEvent(e) {
			t.Fatalf("event %q must be in CanonLifecycleEventTypes", e)
		}
	}
}

// TestSessionTerminatedIsCanonLifecycle asserts the §13 INTEGRATION_CONTRACT
// invariant: collaborator.session.terminated is in the canon set so adapter
// reactors declared against it (Slack on_collaborator_session_terminated,
// GWS, GitHub, Grafana) materialize properly.
func TestSessionTerminatedIsCanonLifecycle(t *testing.T) {
	if EventTypeCollaboratorSessionTerminated != "collaborator.session.terminated" {
		t.Fatalf("constant drift: got %q", EventTypeCollaboratorSessionTerminated)
	}
	if !IsCanonLifecycleEvent(EventTypeCollaboratorSessionTerminated) {
		t.Fatal("session.terminated must be in CanonLifecycleEventTypes")
	}
}
