package httpapi

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
)

func TestPrejournalRefusalRecoveryIDsAndSafeSummary(t *testing.T) {
	pre, parent := uuid.NewString(), uuid.NewString()
	good := `{"preregistration_id":"` + pre + `","refused_retirement_request_id":"` + parent + `"}`
	if a, b, err := decodeFailedInstalledGuestIDs(strings.NewReader(good), "refused_retirement_request_id"); err != nil || a != pre || b != parent {
		t.Fatal(err)
	}
	for _, raw := range []string{`{}`, `null`, `[]`, good + good, strings.Replace(good, `}`, `,"mode":"never_sent"}`, 1), strings.Replace(good, `}`, `,"deadline":"renew"}`, 1), strings.Replace(good, `}`, `,"preregistration_id":"`+pre+`"}`, 1), strings.Replace(good, `"refused_retirement_request_id":"`+parent+`"`, `"refused_retirement_request_id":null`, 1), strings.Replace(good, "refused_retirement_request_id", "expired_retirement_request_id", 1), strings.Replace(good, parent, "00000000-0000-0000-0000-000000000000", 1)} {
		if _, _, err := decodeFailedInstalledGuestIDs(strings.NewReader(raw), "refused_retirement_request_id"); err == nil {
			t.Fatal("caller authority or malformed IDs accepted")
		}
	}
	r := repository.FailedInstalledPrejournalRefusalRecovery{Schema: "failed_installed_prejournal_refusal_recovery_v1", ID: uuid.NewString(), Stage: "issued", DisposalID: uuid.NewString(), PreregistrationID: pre, ParentIntentID: parent, PossibleBusinessEffectsPreserved: true, SuccessorIntent: &model.CapacityGuestRetirementIntent{RequestID: uuid.NewString()}}
	row := prejournalRefusalRecoverySummary(r)
	expected := []string{"schema", "id", "stage", "disposal_id", "preregistration_id", "refused_parent_retirement_request_id", "successor_retirement_request_id", "mode", "original_possible_send_and_HTTP409_preserved", "possible_business_effects_preserved", "maximum_successor_operations", "Guest_quiescence_or_native_cleanup_qualified"}
	if len(row) != len(expected) {
		t.Fatal("public summary fields changed")
	}
	for _, k := range expected {
		if _, ok := row[k]; !ok {
			t.Fatal("missing safe summary field", k)
		}
	}
	wire, err := json.Marshal(row)
	if err != nil || row["mode"] != "prejournal_refusal_not_never_sent" || row["original_possible_send_and_HTTP409_preserved"] != true || row["possible_business_effects_preserved"] != true || row["maximum_successor_operations"] != 1 || row["Guest_quiescence_or_native_cleanup_qualified"] != false || row["successor_retirement_request_id"] != r.SuccessorIntent.RequestID {
		t.Fatal("summary conflated refused/never-sent or minted cleanup", err)
	}
	for _, private := range []string{"refusal_evidence", "original_wire", "original_claimed_intent", "caller_sha256", "lease_owner", "signature", "nonce_sha256"} {
		if strings.Contains(string(wire), private) {
			t.Fatal("private or authority material exported", private)
		}
	}
}
