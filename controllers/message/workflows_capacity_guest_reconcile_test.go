package message

import (
	"context"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

func TestOriginalGuestReconcileSelectsOneOwnedSlot(t *testing.T) {
	t.Run("AWS_native_off_actual_two_read_timestamps", testOriginalAWSNativeOffProducerTimestampJoin)
	p := model.CapacityPolicySpec{Floor: 1, Profiles: []model.CapacityProfile{{Name: "fixed"}}, MutationBindings: []model.CapacityMutationBinding{{ProtectedSlots: 1}}}
	members := []repository.GuestNotifyFloorMember{{Slot: 1, PreregistrationID: "original-1"}, {Slot: 4, PreregistrationID: "original-4"}}
	inv := model.CapacityVMFleetInventory{MissingSlots: []int{3, 2, 5, 6, 7, 8}}
	for _, tc := range []struct {
		name, action, profile string
		units                 int
		want                  string
		slot                  int
		valid                 bool
	}{
		{"create_one", "expand", "fixed", 3, "provision", 2, true},
		{"one_retirement", "drain", "fixed", 1, "retire", 4, true},
		{"batch_forbidden", "expand", "fixed", 4, "", 0, false},
		{"zero_floor_forbidden", "drain", "fixed", 0, "", 0, false},
		{"migration_forbidden", "prepare", "other", 3, "", 0, false},
		{"unknown_is_not_idle", "hold", "fixed", 2, "", 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mode, slot, pre, err := originalGuestNextSlot(p, inv, members, model.CapacityDecision{Action: tc.action, Profile: tc.profile, Units: tc.units})
			if (err == nil) != tc.valid || tc.valid && (mode != tc.want || slot != tc.slot) {
				t.Fatal("new/batch/foreign native lifetime selected", mode, slot, err)
			}
			if mode == "retire" && pre != "original-4" {
				t.Fatal("retire lost original enrollment")
			}
		})
	}
	p.MutationBindings[0].ProtectedSlots = 8
	if _, _, _, err := originalGuestNextSlot(p, inv, members, model.CapacityDecision{Action: "drain", Profile: "fixed", Units: 1}); err == nil {
		t.Fatal("protected native slot selected")
	}
}

func TestOriginalGuestReconcileStepFailsBeforeAnyTransportWithoutOwner(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := executeFailedInstalledGuestRetirementV1(ctx, nil, repository.CapacityStore{}, model.Manifest{}, model.CapacityPolicySpec{GuestRetirementBinding: &model.CapacityGuestRetirementBinding{EvidenceClass: "owned_provisioner_original"}, GuestNotifyCanaryBinding: &model.CapacityGuestNotifyCanaryBinding{}}, model.WorkflowStepSpec{}, guestOriginalStepInput{PreregistrationID: "10000000-0000-4000-8000-000000000001"}, model.CapacityGuestRetirementMemberBinding{}, nil); err == nil {
		t.Fatal("unowned legacy disposal acquired a retirement caller")
	}
	step := model.WorkflowStepSpec{Use: model.WorkflowStepUseSpec{Kind: "yggdrasil", Operation: "capacity.plan_original_guest"}, TimeoutSeconds: 90}
	result := model.WorkflowRunStepResult{Operation: step.Use.Operation, Status: "failed"}
	for _, input := range []map[string]any{{"policy": map[string]any{"namespace": "dakasa-production", "name": "notify-aws-elastic"}}, {"assessment": map[string]any{"healthy": true}}, {"lease_owner": "caller", "generation": 1}} {
		got := executeOriginalGuestReconcileStep(ctx, nil, nil, model.ManifestReference{}, step, result, input)
		if got.Status != "failed" || len(got.Metadata) != 1 || got.Metadata["original_guest_reconcile_refusal_stage"] != "input" {
			t.Fatal("missing SQL/transport/executor became positive")
		}
	}
	if originalGuestReconcileLive(context.Background()) == nil {
		t.Fatal("unbounded original accepted")
	}
}
