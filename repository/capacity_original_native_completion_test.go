package repository

import (
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// This is a pure confirmation-dispatch regression. It creates no SQL grant,
// witness or repository authority; authenticated transactions remain owning.
func TestOriginalMutationCompletionPreservesLegacyAWS(t *testing.T) {
	now := time.Now().UTC()
	legacy := capacityMutationRecord{EventProvider: "aws", Binding: model.CapacityMutationBinding{EnsureCapability: "ensure_ec2_instance", DestroyCapability: "terminate_ec2_instance"}, Grant: model.CapacityMutationGrant{Capability: "ensure_ec2_instance"}, Settlement: &model.CapacityMutationSettleRequest{TransportCompleted: true, ActionID: "actual-legacy-action"}}
	proof := model.CapacityMutationProof{ActionIDs: []string{"actual-legacy-action"}, ActionsTerminal: true, ActionsSuccessful: true}
	for _, tc := range []struct {
		name   string
		change func(*capacityMutationRecord, *model.CapacityMutationProof)
		want   bool
	}{
		{"legacy_aws_without_optional_pin", func(*capacityMutationRecord, *model.CapacityMutationProof) {}, true},
		{"legacy_aws_rejects_new_lifecycle", func(_ *capacityMutationRecord, p *model.CapacityMutationProof) {
			p.AWSInstanceLifecycle = &model.CapacityAWSInstanceLifecycle{}
		}, false},
		{"legacy_aws_rejects_retirement_lifecycle", func(_ *capacityMutationRecord, p *model.CapacityMutationProof) {
			p.AWSRetirementLifecycle = &model.CapacityAWSRetirementLifecycle{}
		}, false},
		{"legacy_aws_still_requires_complete_actions", func(_ *capacityMutationRecord, p *model.CapacityMutationProof) { p.ActionIDs = nil }, false},
		{"legacy_aws_still_rejects_failed_actions", func(_ *capacityMutationRecord, p *model.CapacityMutationProof) { p.ActionsFailed = true }, false},
		{"legacy_aws_still_requires_success", func(_ *capacityMutationRecord, p *model.CapacityMutationProof) { p.ActionsSuccessful = false }, false},
		{"legacy_aws_other_pair_with_source_stays_generic", func(r *capacityMutationRecord, _ *model.CapacityMutationProof) {
			r.Binding.OriginalProviderSourceCommit = strings.Repeat("a", 40)
			r.Binding.EnsureCapability = "ensure_launch_template"
			r.Binding.DestroyCapability = "destroy_launch_template"
			r.Grant.Capability = r.Binding.EnsureCapability
		}, true},
		{"source_pinned_ec2_cannot_use_generic_actions", func(r *capacityMutationRecord, _ *model.CapacityMutationProof) {
			r.Binding.OriginalProviderSourceCommit = strings.Repeat("a", 40)
		}, false},
		{"source_pinned_ec2_retirement_requires_own_original_receipt", func(r *capacityMutationRecord, _ *model.CapacityMutationProof) {
			r.Binding.OriginalProviderSourceCommit = strings.Repeat("a", 40)
			r.Grant.Capability = r.Binding.DestroyCapability
		}, false},
		{"source_pinned_ec2_compensation_does_not_use_create_lifecycle", func(r *capacityMutationRecord, _ *model.CapacityMutationProof) {
			r.Binding.OriginalProviderSourceCommit = strings.Repeat("a", 40)
			r.Grant.CompensationOf = "parent"
		}, true},
		{"other_provider_stays_generic", func(r *capacityMutationRecord, _ *model.CapacityMutationProof) { r.EventProvider = "hetzner" }, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			record := legacy
			actual := proof
			tc.change(&record, &actual)
			if got := successfulOriginalMutationProof(record, actual, now); got != tc.want {
				t.Fatalf("completion=%v want %v", got, tc.want)
			}
		})
	}
}
