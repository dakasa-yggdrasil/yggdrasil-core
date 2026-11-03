package capacity

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// Pure wire/semantic checks only. These unit operands are never persisted as
// a grant, authenticated settlement or native provider authority.
func TestOriginalAWSCreateReturnAndNativeLifecycle(t *testing.T) {
	for _, kind := range []string{"original", "wrong_provider", "wrong_schema", "wrong_status", "wrong_native_id", "invented_next_action", "source_pin", "request_mismatch", "missing_lifecycle", "invented_action_id", "invented_action_flags", "request_id_mismatch", "ec2_pending", "system_initializing", "instance_impaired", "stale_native_status", "different_status_time", "foreign_owner", "foreign_tuple"} {
		t.Run(kind, func(t *testing.T) {
			b, g, settle, reserved, now := originalProviderEnvelopeFixture()
			b.EnsureCapability, b.DestroyCapability = "ensure_ec2_instance", "terminate_ec2_instance"
			g.Capability = b.EnsureCapability
			settle.ResourceID, settle.ActionID, settle.NextActionIDs = "i-1234567890abcdef0", "actual-unit-request-id", []string{}
			r := settle.OriginalProviderCreateReturn
			r.Schema, r.Provider, r.ResponseStatus, r.ResourceID, r.ActionID, r.NextActionIDs = "aws_original_run_instances_return_v1", "aws", 200, settle.ResourceID, settle.ActionID, []string{}
			proof := model.CapacityMutationProof{GrantID: g.GrantID, BindingName: b.Name, Slot: g.Slot, RequestSHA256: g.RequestSHA256, ResourceID: settle.ResourceID, ResourceCreatedAt: settle.ResourceCreatedAt, ObservedCreationGrantID: g.GrantID, ObservedAt: now, OwnerVerified: true, SpecVerified: true, AWSInstanceLifecycle: &model.CapacityAWSInstanceLifecycle{Schema: "aws_original_request_and_instance_status_v1", RequestID: settle.ActionID, EC2State: "running", SystemStatus: "ok", InstanceStatus: "ok", ObservedAt: now}}
			switch kind {
			case "wrong_provider":
				r.Provider = "hetzner"
			case "wrong_schema":
				r.Schema = "hetzner_original_create_return_v1"
			case "wrong_status":
				r.ResponseStatus = 201
			case "wrong_native_id":
				r.ResourceID = "name-adopted"
			case "invented_next_action":
				r.NextActionIDs = []string{"fake-job"}
				settle.NextActionIDs = r.NextActionIDs
			case "source_pin":
				b.OriginalProviderSourceCommit = ""
			case "request_mismatch":
				r.RequestSHA256 = "caller-chosen"
			case "missing_lifecycle":
				proof.AWSInstanceLifecycle = nil
			case "invented_action_id":
				proof.ActionIDs = []string{settle.ActionID}
			case "invented_action_flags":
				proof.ActionsTerminal, proof.ActionsSuccessful = true, true
			case "request_id_mismatch":
				proof.AWSInstanceLifecycle.RequestID = "foreign-request"
			case "ec2_pending":
				proof.AWSInstanceLifecycle.EC2State = "pending"
			case "system_initializing":
				proof.AWSInstanceLifecycle.SystemStatus = "initializing"
			case "instance_impaired":
				proof.AWSInstanceLifecycle.InstanceStatus = "impaired"
			case "stale_native_status":
				proof.ObservedAt = now.Add(-time.Minute)
				proof.AWSInstanceLifecycle.ObservedAt = proof.ObservedAt
			case "different_status_time":
				proof.AWSInstanceLifecycle.ObservedAt = now.Add(-time.Second)
			case "foreign_owner":
				proof.OwnerVerified = false
			case "foreign_tuple":
				proof.ResourceID = "i-00000000000000000"
			}
			_, envelopeErr := ValidateOriginalAWSCreateReturn(b, g, settle.AttemptID, settle, reserved, now)
			complete := envelopeErr == nil && AWSOriginalCreateLifecycleComplete(b, g, &settle, proof, now)
			if complete != (kind == "original") {
				t.Fatalf("AWS original/lifecycle admission %s=%v (%v)", kind, complete, envelopeErr)
			}
			if kind == "original" {
				raw, err := json.Marshal(proof)
				if err != nil {
					t.Fatal(err)
				}
				var roundTrip model.CapacityMutationProof
				if json.Unmarshal(raw, &roundTrip) != nil || !AWSOriginalCreateLifecycleComplete(b, g, &settle, roundTrip, now) {
					t.Fatal("explicit AWS native lifecycle did not round trip")
				}
			}
		})
	}
}
