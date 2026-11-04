//go:build linux && nativequalification

package capacitynativeqemu

import (
	"encoding/json"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"testing"
)

func TestPostlossPendingEnrollmentStageSeparatesHashes(t *testing.T) {
	receipt := model.CapacityGuestOriginalProvisioningReceipt{PreregistrationID: "declared-fixture"}
	stage := Stage{Stage: "original-enrollment-pending-confirmation.json", OriginalRecordSHA256: capacity.GuestRetirementSHA(receipt)}
	got := pendingEnrollmentStage(stage, receipt)
	if got.OriginalRecordSHA256 != capacity.GuestRetirementSHA(receipt) || got.EnrollmentSHA256 != capacity.GuestRetirementSHA(receipt.Enrollment) || got.OriginalRecordSHA256 == got.EnrollmentSHA256 {
		t.Fatal("distinct source values were conflated")
	}
	raw, e := json.Marshal(got)
	var fields map[string]json.RawMessage
	if e != nil || json.Unmarshal(raw, &fields) != nil || len(fields) != 9 || len(fields["original_record_sha256"]) == 0 || len(fields["enrollment_sha256"]) == 0 {
		t.Fatal("pending stage wire changed")
	}
}
