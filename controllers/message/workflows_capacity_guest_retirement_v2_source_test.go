//go:build !nativequalification

package message

import (
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"testing"
)

// Pure polling classification: never a provider/DB authority or delete proof.
func TestOriginalRetirementV2PollsOnlyKnownAcceptedAWSAbsence(t *testing.T) {
	for _, kind := range []string{"known_pending", "uncertain_original", "lost_original", "unknown_inventory", "wrong_request", "wrong_lifetime", "wrong_eni", "duplicate_hold", "unknown_hold", "complete", "writer_claim", "wrong_provider_action", "unknown_lifecycle"} {
		t.Run(kind, func(t *testing.T) {
			r := model.CapacityMutationReceipt{Grant: model.CapacityMutationGrant{GrantID: "destroy", State: "settled"}, Outcome: "accepted", TransportCompleted: true, ResourceID: "i-original", ResourceCreatedAt: "original-created", ActionID: "original-terminate", AuxiliaryInventoryComplete: true, AuxiliaryResources: []model.CapacityMutationAuxiliaryResource{{Kind: "aws_ebs_volume", ID: "vol-original"}, {Kind: "aws_network_interface", ID: "eni-original"}}}
			o := model.CapacityVMRetirementObservation{AWSRetirementLifecycle: &model.CapacityAWSRetirementLifecycle{Schema: "aws_original_terminate_and_native_absence_v1", RequestID: r.ActionID, EC2State: "shutting-down"}, CapacityVMNativeTuple: model.CapacityVMNativeTuple{ID: r.ResourceID, CreatedAt: r.ResourceCreatedAt}, DestroyGrantID: r.Grant.GrantID, DestroyGrantState: r.Grant.State, OriginalOutcome: "accepted", OriginalTransportCompleted: true, ServerStatus: "shutting-down", AuxiliaryInventoryComplete: true, AuxiliaryResources: []model.CapacityVMAuxiliaryObservation{{Kind: r.AuxiliaryResources[0].Kind, ID: r.AuxiliaryResources[0].ID}, {Kind: r.AuxiliaryResources[1].Kind, ID: r.AuxiliaryResources[1].ID}}, HoldReasons: []string{"instance_not_terminated", "aws_ebs_volume_still_present", "aws_network_interface_still_present"}, NextActions: []model.CapacityVMActionObservation{}}
			switch kind {
			case "uncertain_original":
				r.Outcome = "uncertain"
			case "lost_original":
				r.TransportCompleted = false
			case "unknown_inventory":
				r.AuxiliaryInventoryComplete = false
			case "wrong_request":
				o.AWSRetirementLifecycle.RequestID = "other"
			case "wrong_lifetime":
				o.CreatedAt = "other"
			case "wrong_eni":
				o.AuxiliaryResources[1].ID = "other"
			case "duplicate_hold":
				o.HoldReasons = append(o.HoldReasons, o.HoldReasons[0])
			case "unknown_hold":
				o.HoldReasons = []string{"unknown"}
			case "complete":
				o.RetirementComplete = true
			case "writer_claim":
				o.WriterQuiescenceEvidence = true
			case "unknown_lifecycle":
				o.AWSRetirementLifecycle.EC2State = "future"
			case "wrong_provider_action":
				o.DeleteAction = model.CapacityVMRetirementAction{Known: true, ID: r.ActionID}
			}
			if originalAWSRetirementPendingV2(o, r) != (kind == "known_pending") {
				t.Fatal("unknown original gained polling state", kind)
			}
		})
	}
}
