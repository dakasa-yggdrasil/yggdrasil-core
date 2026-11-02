//go:build nativequalification

package capacityqualification

import (
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func TestOriginalReadMutationBinding(t *testing.T) {
	policy := model.CapacityPolicySpec{
		MutationBindings:       []model.CapacityMutationBinding{{Name: "native-qemu", ProfileName: "approved"}},
		GuestRetirementBinding: &model.CapacityGuestRetirementBinding{MutationBindingName: "native-qemu", Members: []model.CapacityGuestRetirementMemberBinding{{Name: "original-qemu-slot-1", Slot: 1}, {Name: "original-qemu-slot-2", Slot: 2}}},
	}
	pre := model.CapacityGuestOriginalProvisioningPreregistration{BindingName: "original-qemu-slot-2", Slot: 2}
	binding, err := OriginalReadMutationBinding(policy, pre)
	if err != nil || binding.Name != "native-qemu" || binding.ProfileName != "approved" {
		t.Fatalf("member name must resolve through mutation binding: %+v %v", binding, err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*model.CapacityPolicySpec, *model.CapacityGuestOriginalProvisioningPreregistration)
	}{
		{"wrong_slot", func(_ *model.CapacityPolicySpec, pre *model.CapacityGuestOriginalProvisioningPreregistration) {
			pre.Slot = 1
		}},
		{"wrong_member", func(_ *model.CapacityPolicySpec, pre *model.CapacityGuestOriginalProvisioningPreregistration) {
			pre.BindingName = "native-qemu"
		}},
		{"missing_guest_binding", func(p *model.CapacityPolicySpec, _ *model.CapacityGuestOriginalProvisioningPreregistration) {
			p.GuestRetirementBinding = nil
		}},
		{"missing_mutation_binding", func(p *model.CapacityPolicySpec, _ *model.CapacityGuestOriginalProvisioningPreregistration) {
			p.GuestRetirementBinding.MutationBindingName = "other"
		}},
		{"duplicate_member", func(p *model.CapacityPolicySpec, _ *model.CapacityGuestOriginalProvisioningPreregistration) {
			p.GuestRetirementBinding.Members = append(p.GuestRetirementBinding.Members, p.GuestRetirementBinding.Members[1])
		}},
		{"duplicate_name", func(p *model.CapacityPolicySpec, _ *model.CapacityGuestOriginalProvisioningPreregistration) {
			p.GuestRetirementBinding.Members = append(p.GuestRetirementBinding.Members, model.CapacityGuestRetirementMemberBinding{Name: "original-qemu-slot-2", Slot: 3})
		}},
		{"duplicate_slot", func(p *model.CapacityPolicySpec, _ *model.CapacityGuestOriginalProvisioningPreregistration) {
			p.GuestRetirementBinding.Members = append(p.GuestRetirementBinding.Members, model.CapacityGuestRetirementMemberBinding{Name: "other", Slot: 2})
		}},
		{"duplicate_mutation", func(p *model.CapacityPolicySpec, _ *model.CapacityGuestOriginalProvisioningPreregistration) {
			p.MutationBindings = append(p.MutationBindings, p.MutationBindings[0])
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			copyPolicy := policy
			copyPolicy.MutationBindings = append([]model.CapacityMutationBinding(nil), policy.MutationBindings...)
			copyGuest := *policy.GuestRetirementBinding
			copyGuest.Members = append([]model.CapacityGuestRetirementMemberBinding(nil), copyGuest.Members...)
			copyPolicy.GuestRetirementBinding = &copyGuest
			copyPre := pre
			tc.mutate(&copyPolicy, &copyPre)
			if _, err := OriginalReadMutationBinding(copyPolicy, copyPre); err == nil {
				t.Fatal("unmatched or ambiguous binding accepted")
			}
		})
	}
}
