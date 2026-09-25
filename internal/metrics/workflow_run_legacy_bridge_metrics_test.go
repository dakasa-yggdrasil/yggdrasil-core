package metrics

import "testing"

// ADR-0022: the legacy workflow-run bridge families must render a bounded
// label set, every bump must land in exactly one bucket, and unknown routes
// must be no-ops.

func TestIncWorkflowRunLegacyBridgeRequest_CountsByRoute(t *testing.T) {
	ResetForTest()
	IncWorkflowRunLegacyBridgeRequest(WorkflowRunLegacyBridgeRouteDispatch)
	IncWorkflowRunLegacyBridgeRequest(WorkflowRunLegacyBridgeRoutePoll)
	IncWorkflowRunLegacyBridgeRequest(WorkflowRunLegacyBridgeRoutePoll)
	IncWorkflowRunLegacyBridgeRequest("unknown")
	IncWorkflowRunLegacyBridgeRequest("")

	snap := WorkflowRunLegacyBridgeRequestsSnapshot()
	if len(snap) != 2 {
		t.Fatalf("snapshot has %d routes, want exactly 2: %v", len(snap), snap)
	}
	if snap[WorkflowRunLegacyBridgeRouteDispatch] != 1 || snap[WorkflowRunLegacyBridgeRoutePoll] != 2 {
		t.Fatalf("snapshot=%v, want dispatch=1 poll=2", snap)
	}
}

func TestWorkflowRunLegacyBridgeAuditFailuresCountAndReset(t *testing.T) {
	ResetForTest()
	IncWorkflowRunLegacyBridgeAuditFailure()
	IncWorkflowRunLegacyBridgeAuditFailure()
	if got := WorkflowRunLegacyBridgeAuditFailuresSnapshot(); got != 2 {
		t.Fatalf("audit failures=%d, want 2", got)
	}
	IncWorkflowRunLegacyBridgeRequest(WorkflowRunLegacyBridgeRouteDispatch)
	ResetForTest()
	if got := WorkflowRunLegacyBridgeAuditFailuresSnapshot(); got != 0 {
		t.Fatalf("ResetForTest left audit failures=%d", got)
	}
	for route, value := range WorkflowRunLegacyBridgeRequestsSnapshot() {
		if value != 0 {
			t.Fatalf("ResetForTest left %s=%d", route, value)
		}
	}
}
