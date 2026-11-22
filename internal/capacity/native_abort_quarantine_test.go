package capacity

import (
	"encoding/json"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
	"testing"
	"time"
)

func nativeAbortQuarantineFixture() (model.Manifest, model.CapacityPolicySpec, model.CapacityNativeAbortQuarantineBinding, model.AdapterCapacityPodUnregisteredTerminalResponse, time.Time) {
	policy, p, proof := nativeAbortRecoveryFixture()
	b := model.CapacityNativeAbortQuarantineBinding{Schema: NativeAbortQuarantineSchema, Confirmation: "QUARANTINE UNKNOWN ONLY", Native: proof.Binding.Native, ParentCommandID: proof.Binding.ParentCommandID, CommandID: uuid.NewString(), ExpectedIntentFencingToken: 69}
	o := model.NativePreRegistrationAbortObservation{NativeTerminationObservation: model.NativeTerminationObservation{BindingName: b.Native.BindingName, Namespace: b.Native.Namespace, PodName: b.Native.PodName, State: "absent", Reason: "native_name_absent", ObservedAt: proof.AuthoredAt}}
	r := model.AdapterCapacityPodUnregisteredTerminalResponse{Operation: ObserveNativeUnregisteredTerminal, Status: "observed", Observation: o, Metadata: map[string]any{"atomic_snapshot": false, "useful_capacity_known": false, "physical_capacity_released": false, "sdk_lane_witness": false}}
	return policy, p, b, r, proof.AuthoredAt
}
func TestNativeAbortQuarantineClosedAbsence(t *testing.T) {
	for _, name := range []string{"exact_absence", "same_name_foreign_uid", "present_unprotected", "stale", "sdk_receipt", "ready_claim", "private_metadata", "fake_lane", "empty_confirmation", "wrong_policy", "parent_is_child"} {
		t.Run(name, func(t *testing.T) {
			policy, p, b, r, now := nativeAbortQuarantineFixture()
			switch name {
			case "same_name_foreign_uid":
				r.Observation.PodUID = uuid.NewString()
			case "present_unprotected":
				r.Observation.State = "failed_deleting"
			case "stale":
				r.Observation.ObservedAt = now.Add(-time.Hour)
			case "sdk_receipt":
				r.Observation.Receipt = &model.NativePodTerminationReceipt{}
			case "ready_claim":
				r.Observation.AdmissionReady = true
			case "private_metadata":
				r.Metadata["return_nonce"] = "forged"
			case "fake_lane":
				r.Metadata["sdk_lane_witness"] = true
			case "empty_confirmation":
				b.Confirmation = ""
			case "wrong_policy":
				b.Native.PolicyID = uuid.NewString()
			case "parent_is_child":
				b.ParentCommandID = b.CommandID
			}
			good := ValidateNativeAbortQuarantineBinding(policy, p, b) == nil && ValidateNativeAbortQuarantineAbsence(p, b.Native, r, now) == nil
			if good != (name == "exact_absence") {
				t.Fatal("administrative quarantine accepted unsupported absence or caller proof")
			}
		})
	}
}
func TestNativeAbortQuarantineClosedInput(t *testing.T) {
	_, _, b, _, _ := nativeAbortQuarantineFixture()
	raw, _ := json.Marshal(b)
	var fields map[string]any
	_ = json.Unmarshal(raw, &fields)
	for _, key := range []string{"authority_token", "confirmed", "original_result", "caller_ack_at", "skip_history"} {
		fields[key] = true
		var out model.CapacityNativeAbortQuarantineBinding
		if DecodeNativeCapacity(fields, &out) == nil {
			t.Fatal("public administrative binding accepted authority or outcome field")
		}
		delete(fields, key)
	}
}
