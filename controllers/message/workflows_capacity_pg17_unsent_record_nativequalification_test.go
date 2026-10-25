//go:build linux && nativequalification

package message

import (
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// This regression exercises the exact predicate called after the original DB
// read. It supplies no execution authority and does not simulate a native action.
func TestPG17OriginalUnsentRecordCanonicalState(t *testing.T) {
	base := pg17MutationRecord{
		PolicyID:   "policy",
		WorkflowID: "workflow",
		Grant:      model.CapacityMutationGrant{State: "rejected"},
		Settlement: &model.CapacityMutationSettleRequest{Outcome: "rejected_before_send"},
	}
	digest := capacity.GuestRetirementSHA(*base.Settlement)
	cases := []struct {
		name   string
		change func(*pg17MutationRecord, *string)
		want   bool
	}{
		{name: "canonical_rejected", want: true},
		{name: "settled_is_not_unsent_terminal", change: func(r *pg17MutationRecord, _ *string) { r.Grant.State = "settled" }},
		{name: "redeemed_is_not_terminal", change: func(r *pg17MutationRecord, _ *string) { r.Grant.State = "redeemed" }},
		{name: "wrong_policy", change: func(r *pg17MutationRecord, _ *string) { r.PolicyID = "foreign-policy" }},
		{name: "wrong_workflow", change: func(r *pg17MutationRecord, _ *string) { r.WorkflowID = "foreign-workflow" }},
		{name: "missing_settlement", change: func(r *pg17MutationRecord, _ *string) { r.Settlement = nil }},
		{name: "wrong_outcome", change: func(r *pg17MutationRecord, _ *string) { r.Settlement.Outcome = "accepted" }},
		{name: "provider_rejected_is_distinct", change: func(r *pg17MutationRecord, _ *string) { r.Settlement.Outcome = "provider_rejected" }},
		{name: "resource_present", change: func(r *pg17MutationRecord, _ *string) { r.Settlement.ResourceID = "resource" }},
		{name: "wrong_hash", change: func(_ *pg17MutationRecord, sha *string) { *sha = "wrong" }},
		{name: "changed_settlement", change: func(r *pg17MutationRecord, _ *string) { r.Settlement.ActionID = "changed" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := base
			settlement := *base.Settlement
			r.Settlement = &settlement
			sha := digest
			if tc.change != nil {
				tc.change(&r, &sha)
			}
			if got := pg17OriginalUnsentRecordValid(r, "policy", "workflow", sha); got != tc.want {
				t.Fatalf("stored unsent assertion: got %t, want %t", got, tc.want)
			}
		})
	}
}
