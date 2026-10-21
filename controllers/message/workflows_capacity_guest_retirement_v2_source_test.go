//go:build !nativequalification

package message

import (
	"encoding/json"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/manifest"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"os"
	"strings"
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

func TestOriginalRetirementV2RequiresExactProviderOwnedCatalog(t *testing.T) {
	raw, err := os.ReadFile("../../repository/testdata/capacity_hetzner_type_v030.json")
	if err != nil {
		t.Fatal(err)
	}
	var original model.Manifest
	if json.Unmarshal(raw, &original) != nil {
		t.Fatal("owning source catalog malformed")
	}
	for _, version := range []string{"0.3.0", "0.3.2"} {
		for _, kind := range []string{"exact", "old_create_only", "future_version", "missing_destroy", "missing_retirement", "not_idempotent", "missing_native_default", "foreign_source", "wrong_version_source", "duplicate_retirement"} {
			t.Run(version+"/"+kind, func(t *testing.T) {
				ts, err := manifest.ParseIntegrationTypeSpec(original.Spec)
				if err != nil {
					t.Fatal(err)
				}
				ts.Adapter.Version = version
				source := originalHetznerRetirementV3Source
				if version == "0.3.2" {
					source = originalHetznerRetirementV032Source
				}
				switch kind {
				case "old_create_only":
					ts.Adapter.Version = "0.2.0"
				case "future_version":
					ts.Adapter.Version = "0.3.1"
				case "foreign_source":
					source = strings.Repeat("a", 40)
				case "wrong_version_source":
					if version == "0.3.2" {
						source = originalHetznerRetirementV3Source
					} else {
						source = originalHetznerRetirementV032Source
					}
				case "missing_destroy":
					for n, a := range ts.ActionCatalog {
						if a.Name == "destroy_server" {
							ts.ActionCatalog = append(ts.ActionCatalog[:n], ts.ActionCatalog[n+1:]...)
							break
						}
					}
				case "missing_retirement":
					for n, a := range ts.ActionCatalog {
						if a.Name == capacity.VMObserveRetirement {
							ts.ActionCatalog = append(ts.ActionCatalog[:n], ts.ActionCatalog[n+1:]...)
							break
						}
					}
				case "not_idempotent":
					for n := range ts.ActionCatalog {
						if ts.ActionCatalog[n].Name == capacity.VMObserveRetirement {
							ts.ActionCatalog[n].Idempotent = false
						}
					}
				case "missing_native_default":
					for n := range ts.ResourceTypes {
						if ts.ResourceTypes[n].Name == "server" {
							ts.ResourceTypes[n].DefaultActions = []string{"ensure_server", "destroy_server", capacity.VMObserveServer}
						}
					}
				case "duplicate_retirement":
					for _, a := range ts.ActionCatalog {
						if a.Name == capacity.VMObserveRetirement {
							ts.ActionCatalog = append(ts.ActionCatalog, a)
							break
						}
					}
				}
				allowed := productionRetirementCatalogV2("hetzner", ts) && originalGuestSupplierCatalogSourceFor("hetzner", ts, source)
				if allowed != (kind == "exact") {
					t.Fatal("unowned retirement capability/source admitted", kind)
				}
			})
		}
	}
}

func TestOriginalRetirementV2PollsOnlyKnownAcceptedHetznerAbsence(t *testing.T) {
	for _, kind := range []string{"known_pending", "unknown_original", "wrong_main_action", "native_action_error", "wrong_tuple", "wrong_primary_ip", "unknown_hold", "completed", "provider_fencing", "provider_quiescence", "foreign_lifecycle"} {
		t.Run(kind, func(t *testing.T) {
			r := model.CapacityMutationReceipt{Grant: model.CapacityMutationGrant{GrantID: "destroy", State: "settled"}, Outcome: "accepted", TransportCompleted: true, ResourceID: "100", ResourceCreatedAt: "original-created", ActionID: "500", NextActionIDs: []string{}, AuxiliaryInventoryComplete: true, AuxiliaryResources: []model.CapacityMutationAuxiliaryResource{{Kind: "primary_ip", ID: "200", RequiresAbsence: true}}}
			// Current official ServerDeleteResponse has only Action. No IP-only native
			// successor is invented to make this synthetic polling operand succeed.
			o := model.CapacityVMRetirementObservation{CapacityVMNativeTuple: model.CapacityVMNativeTuple{ID: r.ResourceID, CreatedAt: r.ResourceCreatedAt}, DestroyGrantID: r.Grant.GrantID, DestroyGrantState: r.Grant.State, OriginalOutcome: "accepted", OriginalTransportCompleted: true, ServerAbsenceComplete: true, ServerStatus: "deleting", DeleteAction: model.CapacityVMRetirementAction{Known: true, Observed: true, ID: r.ActionID, Status: "running", Command: "delete_server"}, NextActions: []model.CapacityVMActionObservation{}, AuxiliaryInventoryComplete: true, AuxiliaryResources: []model.CapacityVMAuxiliaryObservation{{Kind: "primary_ip", ID: "200"}}, HoldReasons: []string{"native_server_present", "original_delete_actions_not_successful", "native_billable_resources_present"}}
			switch kind {
			case "unknown_original":
				r.Outcome = "uncertain"
			case "wrong_main_action":
				o.DeleteAction.ID = "other"
			case "native_action_error":
				o.DeleteAction.Status = "error"
			case "wrong_tuple":
				o.CreatedAt = "other"
			case "wrong_primary_ip":
				o.AuxiliaryResources[0].ID = "other"
			case "unknown_hold":
				o.HoldReasons = []string{"unknown"}
			case "completed":
				o.RetirementComplete = true
			case "provider_fencing":
				o.ProviderFencingEvidence = true
			case "provider_quiescence":
				o.WriterQuiescenceEvidence = true
			case "foreign_lifecycle":
				o.AWSRetirementLifecycle = &model.CapacityAWSRetirementLifecycle{}
			}
			if originalHetznerRetirementPendingV2(o, r) != (kind == "known_pending") {
				t.Fatal("unknown original became pollable", kind)
			}
		})
	}
}
