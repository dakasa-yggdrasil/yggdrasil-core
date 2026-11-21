package capacity

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

func reviewedAbortFixture() (model.Manifest, model.CapacityPolicySpec, model.CapacityNativeAbortProof) {
	policy, p, proof := nativeAbortFixture()
	proof.Schema, proof.Binding.Schema = NativePreRegistrationAbortReviewedQuarantineSchema, NativePreRegistrationAbortReviewedQuarantineSchema
	proof.Binding.ReviewedQuarantines = &model.CapacityNativeAbortQuarantineReview{Receipts: []model.CapacityNativeAbortQuarantineReference{{CommandID: "11111111-1111-4111-8111-111111111111", SubjectUID: uuid.NewString(), RecordSHA256: strings.Repeat("a", 64)}}}
	proof.ScopeUnsettledCommands = 1
	proof.ReviewedQuarantineCounts = &model.CapacityNativeUnsettledCounts{RawUnsettled: 1, Quarantined: 1}
	return policy, p, proof
}

func TestNativeAbortReviewedQuarantineProof(t *testing.T) {
	for _, mode := range []string{"exact", "missing_review", "empty_review", "same_target", "wrong_receipt_digest", "duplicate_command", "duplicate_subject", "unordered", "wrong_count", "fake_raw_zero", "active_unknown", "missing_counts", "wrong_schema", "target_lifetime", "target_archive", "target_legacy", "target_identity", "target_hot", "target_command_archive", "running", "restarted", "admitted", "challenge", "receipt", "stale"} {
		t.Run(mode, func(t *testing.T) {
			policy, p, proof := reviewedAbortFixture()
			switch mode {
			case "missing_review":
				proof.Binding.ReviewedQuarantines = nil
			case "empty_review":
				proof.Binding.ReviewedQuarantines.Receipts = nil
			case "same_target":
				proof.Binding.ReviewedQuarantines.Receipts[0].SubjectUID = proof.Binding.PodUID
			case "wrong_receipt_digest":
				proof.Binding.ReviewedQuarantines.Receipts[0].RecordSHA256 = "bad"
			case "duplicate_command", "duplicate_subject", "unordered":
				ref := proof.Binding.ReviewedQuarantines.Receipts[0]
				second := ref
				if mode != "duplicate_command" {
					second.CommandID = "ffffffff-ffff-4fff-bfff-ffffffffffff"
				}
				if mode != "duplicate_subject" {
					second.SubjectUID = uuid.NewString()
				}
				proof.Binding.ReviewedQuarantines.Receipts = append(proof.Binding.ReviewedQuarantines.Receipts, second)
				if mode == "unordered" {
					proof.Binding.ReviewedQuarantines.Receipts[0], proof.Binding.ReviewedQuarantines.Receipts[1] = second, ref
				}
				proof.ScopeUnsettledCommands = 2
				proof.ReviewedQuarantineCounts.RawUnsettled, proof.ReviewedQuarantineCounts.Quarantined = 2, 2
			case "wrong_count":
				proof.ReviewedQuarantineCounts.Quarantined = 0
			case "fake_raw_zero":
				proof.ScopeUnsettledCommands = 0
			case "active_unknown":
				proof.ReviewedQuarantineCounts.ActiveUnsettled = 1
			case "missing_counts":
				proof.ReviewedQuarantineCounts = nil
			case "wrong_schema":
				proof.Binding.Schema = NativePreRegistrationAbortSchema
			case "target_lifetime":
				proof.ZeroHistory.Lifetimes = 1
			case "target_archive":
				proof.ZeroHistory.LifetimeArchives = 1
			case "target_legacy":
				proof.ZeroHistory.LegacyCheckpoints = 1
			case "target_identity":
				proof.ZeroHistory.CommandIdentities = 1
			case "target_hot":
				proof.ZeroHistory.HotCommands = 1
			case "target_command_archive":
				proof.ZeroHistory.ArchivedCommands = 1
			case "running":
				proof.Observation.ContainerState = "running"
			case "restarted":
				proof.Observation.RestartCount = 1
			case "admitted":
				proof.Observation.AdmissionReady = true
			case "challenge":
				proof.Observation.ChallengeState = "present"
			case "receipt":
				proof.Observation.Receipt = &model.NativePodTerminationReceipt{}
			case "stale":
				proof.AuthoredAt = time.Now().Add(-2 * time.Minute)
			}
			if err := ValidateNativeManualAbortProof(policy, p, proof, time.Now().UTC()); (err == nil) != (mode == "exact") {
				t.Fatalf("reviewed abort eligibility %s: %v", mode, err)
			}
			if ValidateNativeAbortProof(policy, p, proof, time.Now().UTC()) == nil {
				t.Fatal("v2 entered legacy raw-zero proof")
			}
		})
	}
}

func TestNativeAbortReviewedQuarantineLegacyClosed(t *testing.T) {
	for _, mode := range []string{"binding_null", "binding_review", "proof_null", "proof_counts"} {
		t.Run(mode, func(t *testing.T) {
			_, _, proof := nativeAbortFixture()
			raw, err := json.Marshal(proof)
			if err != nil {
				t.Fatal(err)
			}
			var obj map[string]any
			if json.Unmarshal(raw, &obj) != nil {
				t.Fatal("fixture JSON")
			}
			switch mode {
			case "binding_null":
				obj["binding"].(map[string]any)["reviewed_quarantines"] = nil
			case "binding_review":
				obj["binding"].(map[string]any)["reviewed_quarantines"] = map[string]any{"receipts": []any{}}
			case "proof_null":
				obj["reviewed_quarantine_counts"] = nil
			case "proof_counts":
				obj["reviewed_quarantine_counts"] = map[string]any{"raw_unsettled_commands": 0, "quarantined_commands": 0, "active_unsettled_commands": 0}
			}
			var decoded model.CapacityNativeAbortProof
			if DecodeNativeCapacity(obj, &decoded) == nil {
				t.Fatal("legacy review member normalized away")
			}
		})
	}
}
