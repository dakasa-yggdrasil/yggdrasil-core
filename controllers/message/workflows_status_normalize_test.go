package message

import "testing"

// TestNormalizeWorkflowIntegrationStatus_IdempotentOutcomes locks in the
// success bucket for the workflow engine: any adapter response that maps
// to a benign or idempotency-friendly outcome must collapse to "succeeded"
// so cleanup / re-run workflows do not flap red.
func TestNormalizeWorkflowIntegrationStatus_IdempotentOutcomes(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		input  string
		expect string
	}{
		// Generic green-path statuses
		{"empty", "", "succeeded"},
		{"ok", "ok", "succeeded"},
		{"done", "done", "succeeded"},
		{"completed", "completed", "succeeded"},
		{"dispatched", "dispatched", "succeeded"},
		{"succeeded", "succeeded", "succeeded"},
		{"success", "success", "succeeded"},

		// Declarative adapter verbs (k8s, grafana, rabbitmq topology)
		{"applied", "applied", "succeeded"},
		{"observed", "observed", "succeeded"},
		{"ensured", "ensured", "succeeded"},

		// Mutation outcomes
		{"created", "created", "succeeded"},
		{"updated", "updated", "succeeded"},
		{"already_exists", "already_exists", "succeeded"},

		// Idempotent delete / cleanup outcomes — re-running a teardown
		// against a missing object MUST NOT fail the workflow run.
		{"not_found", "not_found", "succeeded"},
		{"absent", "absent", "succeeded"},
		{"deleted", "deleted", "succeeded"},

		// Dry-run / simulated mode — adapter reports what it WOULD do.
		{"simulated", "simulated", "succeeded"},
		{"dry_run", "dry_run", "succeeded"},
		{"noop", "noop", "succeeded"},
		{"no_op", "no_op", "succeeded"},

		// Case / whitespace insensitivity
		{"upper not_found", "NOT_FOUND", "succeeded"},
		{"padded simulated", "  simulated  ", "succeeded"},
		{"mixed deleted", " Deleted ", "succeeded"},

		// Anything outside the allowlist must still fail.
		{"failed", "failed", "failed"},
		{"error", "error", "failed"},
		{"timeout", "timeout", "failed"},
		{"blocked", "blocked", "failed"},
		{"rejected", "rejected", "failed"},
		{"unknown", "totally-made-up", "failed"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := normalizeWorkflowIntegrationStatus(tc.input)
			if got != tc.expect {
				t.Fatalf("normalizeWorkflowIntegrationStatus(%q) = %q, want %q", tc.input, got, tc.expect)
			}
		})
	}
}
