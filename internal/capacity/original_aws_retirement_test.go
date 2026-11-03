package capacity

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// Semantic operands only: no test creates a grant, signed witness, SQL record
// or authenticated provider authority. Actual SDK TLS transport is adapter-owned.
func awsDestroyFixture() (model.CapacityPolicySpec, model.CapacityMutationBinding, model.CapacityMutationGrant, model.CapacityMutationSettleRequest, model.CapacityVMRetirementObservation, time.Time, time.Time) {
	p, b, r, o, now := vmRetirementFixture()
	b.OriginalProviderSourceCommit = strings.Repeat("a", 40)
	b.EnsureCapability = "ensure_ec2_instance"
	b.DestroyCapability = "terminate_ec2_instance"
	g := r.Grant
	g.GrantID = "12345678-1234-4234-8234-123456789012"
	g.RequestSHA256 = strings.Repeat("b", 64)
	g.Capability = b.DestroyCapability
	g.ExpectedResourceID = "i-1234567890abcdef0"
	g.ExpiresAt = now.Add(time.Minute)
	aux := []model.CapacityMutationAuxiliaryResource{{Kind: "aws_ebs_volume", ID: "vol-1234567890abcdef0", RequiresAbsence: true}, {Kind: "aws_network_interface", ID: "eni-1234567890abcdef0", RequiresAbsence: true}}
	issued := now.Add(-5 * time.Second)
	s := model.CapacityMutationSettleRequest{GrantID: g.GrantID, AttemptID: "12345678-1234-4234-8234-123456789013", RequestSHA256: g.RequestSHA256, Outcome: "accepted", TransportCompleted: true, ResourceID: g.ExpectedResourceID, ResourceCreatedAt: g.ExpectedResourceCreatedAt, ActionID: "native-terminate-request", NextActionIDs: []string{}, ObservedAt: now.Add(-3 * time.Second).Format(time.RFC3339Nano), AuxiliaryResources: aux, AuxiliaryInventoryComplete: true}
	s.OriginalProviderDestroyReturn = &model.CapacityOriginalProviderDestroyReturn{Schema: "aws_original_terminate_instances_return_v1", Provider: "aws", AdapterSourceCommit: b.OriginalProviderSourceCommit, GrantID: g.GrantID, AttemptID: s.AttemptID, RequestSHA256: g.RequestSHA256, ResourceID: s.ResourceID, ResourceCreatedAt: s.ResourceCreatedAt, ActionID: s.ActionID, NextActionIDs: []string{}, CalledAt: issued.Add(time.Millisecond).Format(time.RFC3339Nano), ReturnedAt: issued.Add(time.Second).Format(time.RFC3339Nano), ContextDeadline: g.ExpiresAt.Format(time.RFC3339Nano), ResponseStatus: 200, ResponseBodySHA256: strings.Repeat("c", 64), ResponseBytes: 512}
	o.ID = s.ResourceID
	o.DestroyGrantID = g.GrantID
	o.DeleteAction = model.CapacityVMRetirementAction{}
	o.BillingExposure = nil
	o.AuxiliaryResources = []model.CapacityVMAuxiliaryObservation{{Kind: aux[0].Kind, ID: aux[0].ID, Absent: true, ObservedAt: now.Add(-time.Second).Format(time.RFC3339Nano)}, {Kind: aux[1].Kind, ID: aux[1].ID, Absent: true, ObservedAt: now.Format(time.RFC3339Nano)}}
	o.AWSRetirementLifecycle = &model.CapacityAWSRetirementLifecycle{Schema: "aws_original_terminate_and_native_absence_v1", RequestID: s.ActionID, EC2State: "terminated", ObservedAt: now}
	return p, b, g, s, o, issued, now
}
func TestOriginalAWSDestroyReceiptAndNativeAbsence(t *testing.T) {
	for _, kind := range []string{"original_terminated", "original_native_not_found", "missing_original", "create_receipt_reuse", "wrong_source", "wrong_grant", "wrong_attempt", "wrong_request", "old_native_creation_allowed", "wrong_lifetime", "early_call", "renewed_deadline", "late_return", "incomplete_transport", "unknown_outcome", "missing_eni_inventory", "different_eni", "retained_volume", "retained_eni", "retained_instance", "uncertain_absence", "fake_job", "fake_action_flags", "create_lifecycle_reuse", "missing_lifecycle", "wrong_lifecycle_request", "stale_native_read", "wrong_binding", "protected_slot", "compensation_without_contract", "invoice_claim", "writer_quiescence_claim"} {
		t.Run(kind, func(t *testing.T) {
			p, b, g, s, o, issued, now := awsDestroyFixture()
			switch kind {
			case "original_native_not_found":
				o.AWSRetirementLifecycle.EC2State = "not_found"
			case "missing_original":
				s.OriginalProviderDestroyReturn = nil
			case "create_receipt_reuse":
				s.OriginalProviderCreateReturn = s.OriginalProviderDestroyReturn
				s.OriginalProviderDestroyReturn = nil
			case "wrong_source":
				s.OriginalProviderDestroyReturn.AdapterSourceCommit = strings.Repeat("e", 40)
			case "wrong_grant":
				s.OriginalProviderDestroyReturn.GrantID = "12345678-1234-4234-8234-123456789014"
			case "wrong_attempt":
				s.OriginalProviderDestroyReturn.AttemptID = "12345678-1234-4234-8234-123456789014"
			case "wrong_request":
				s.OriginalProviderDestroyReturn.RequestSHA256 = strings.Repeat("e", 64)
			case "old_native_creation_allowed":
			case "wrong_lifetime":
				s.OriginalProviderDestroyReturn.ResourceCreatedAt = now.Add(-time.Hour * 24).Format(time.RFC3339Nano)
			case "early_call":
				s.OriginalProviderDestroyReturn.CalledAt = issued.Add(-time.Millisecond).Format(time.RFC3339Nano)
			case "renewed_deadline":
				s.OriginalProviderDestroyReturn.ContextDeadline = g.ExpiresAt.Add(time.Second).Format(time.RFC3339Nano)
			case "late_return":
				s.OriginalProviderDestroyReturn.ReturnedAt = g.ExpiresAt.Format(time.RFC3339Nano)
			case "incomplete_transport":
				s.TransportCompleted = false
			case "unknown_outcome":
				s.Outcome = "uncertain"
			case "missing_eni_inventory":
				s.AuxiliaryResources = s.AuxiliaryResources[:1]
			case "different_eni":
				o.AuxiliaryResources[1].ID = "eni-00000000000000000"
			case "retained_volume":
				o.AuxiliaryResources[0].Absent = false
			case "retained_eni":
				o.AuxiliaryResources[1].Absent = false
			case "retained_instance":
				o.ServerAbsent = false
				o.ServerStatus = "shutting-down"
			case "uncertain_absence":
				o.ServerAbsenceComplete = false
			case "fake_job":
				o.DeleteAction = model.CapacityVMRetirementAction{Known: true, Observed: true, ID: s.ActionID, Status: "success", Command: "delete_server"}
			case "missing_lifecycle":
				o.AWSRetirementLifecycle = nil
			case "wrong_lifecycle_request":
				o.AWSRetirementLifecycle.RequestID = "foreign"
			case "stale_native_read":
				o.ObservedAt = now.Add(-time.Minute).Format(time.RFC3339Nano)
			case "wrong_binding":
				b.OriginalProviderSourceCommit = ""
			case "protected_slot":
				g.Slot = 1
			case "compensation_without_contract":
				g.CompensationOf = "parent"
			case "invoice_claim":
				o.InvoiceReconciled = true
			case "writer_quiescence_claim":
				o.WriterQuiescenceEvidence = true
			}
			receipt := model.CapacityMutationReceipt{Grant: g, AttemptID: s.AttemptID, Outcome: s.Outcome, TransportCompleted: s.TransportCompleted, ResourceID: s.ResourceID, ResourceCreatedAt: s.ResourceCreatedAt, ActionID: s.ActionID, NextActionIDs: s.NextActionIDs, AuxiliaryResources: s.AuxiliaryResources, AuxiliaryInventoryComplete: s.AuxiliaryInventoryComplete}
			proof, e := VMRetirementProof(p, b, receipt, o, now, "receipt:actual-native")
			if kind == "fake_action_flags" {
				proof.ActionsSuccessful = true
			}
			if kind == "create_lifecycle_reuse" {
				proof.AWSInstanceLifecycle = &model.CapacityAWSInstanceLifecycle{}
			}
			_, env := ValidateOriginalAWSDestroyReturn(b, g, s.AttemptID, s, issued, now)
			good := e == nil && env == nil && AWSOriginalDestroyLifecycleComplete(b, g, &s, proof, now)
			want := kind == "original_terminated" || kind == "original_native_not_found" || kind == "old_native_creation_allowed"
			if good != want {
				t.Fatalf("admission=%v want=%v read=%v original=%v", good, want, e, env)
			}
			if good {
				raw, _ := json.Marshal(proof)
				var round model.CapacityMutationProof
				if json.Unmarshal(raw, &round) != nil || !AWSOriginalDestroyLifecycleComplete(b, g, &s, round, now) || len(round.ActionIDs) != 0 || round.ActionsSuccessful || len(round.AuxiliaryAbsent) != 2 {
					t.Fatal("explicit native absence was replaced by invented actions")
				}
			}
		})
	}
}
