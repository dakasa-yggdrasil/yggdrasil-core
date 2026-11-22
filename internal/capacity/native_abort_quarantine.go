package capacity

import (
	"fmt"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"strings"
	"time"
)

const NativeAbortQuarantineSchema = "native_uncertain_abort_quarantine_v1"
const QuarantineUncertainNativeBirth = "capacity.quarantine_uncertain_native_birth"

func ValidateNativeAbortQuarantineBinding(policy model.Manifest, p model.CapacityPolicySpec, b model.CapacityNativeAbortQuarantineBinding) error {
	if b.Schema != NativeAbortQuarantineSchema || b.Confirmation == "" || len(b.Confirmation) > 128 || strings.ContainsAny(b.Confirmation, "\r\n\t") || ValidateNativeAbortBinding(policy, p, b.Native) != nil || !NativeProcessNonce(b.ParentCommandID) || !NativeProcessNonce(b.CommandID) || b.ParentCommandID == b.CommandID || b.CommandID == b.Native.PodUID || b.ExpectedIntentFencingToken < 1 || b.ExpectedIntentFencingToken >= 9007199254740991 {
		return fmt.Errorf("closed human native uncertain-abort quarantine binding required")
	}
	return nil
}

// Only a fresh server-owned GET reporting actual name absence is eligible.
// A present same-name replacement, unprotected object, or old terminal witness
// is not absence. This receipt never attributes deletion to the old command.
func ValidateNativeAbortQuarantineAbsence(p model.CapacityPolicySpec, b model.CapacityNativeAbortBinding, r model.AdapterCapacityPodUnregisteredTerminalResponse, now time.Time) error {
	o := r.Observation
	if len(r.Metadata) != 4 || r.Metadata["atomic_snapshot"] != false || r.Metadata["useful_capacity_known"] != false || r.Metadata["physical_capacity_released"] != false || r.Metadata["sdk_lane_witness"] != false {
		return fmt.Errorf("closed detail-free native absence metadata required")
	}
	if r.Operation != ObserveNativeUnregisteredTerminal || r.Status != "observed" || o.Namespace != b.Namespace || o.PodName != b.PodName || o.BindingName != b.BindingName || o.State != "absent" || o.Reason != "native_name_absent" || o.PodUID != "" || o.Protected || o.AdmissionReady || o.Receipt != nil || o.ReceiptSHA256 != "" || !Fresh(o.ObservedAt, now, p.MaxEvidenceAgeSeconds) {
		return fmt.Errorf("fresh original-name native absence required for administrative quarantine")
	}
	return nil
}
