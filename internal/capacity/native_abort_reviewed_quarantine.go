package capacity

import (
	"encoding/json"
	"fmt"
	"reflect"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// Presence is significant: a null review field must not silently normalize
// into an unchanged legacy binding/proof before its owner validates it.
func nativeAbortClosedLegacyMembers(typ reflect.Type, members map[string]json.RawMessage) error {
	var field string
	switch typ {
	case reflect.TypeOf(model.CapacityNativeAbortBinding{}):
		field = "reviewed_quarantines"
	case reflect.TypeOf(model.CapacityNativeAbortProof{}):
		field = "reviewed_quarantine_counts"
	default:
		return nil
	}
	var schema string
	if json.Unmarshal(members["schema"], &schema) == nil && schema == NativePreRegistrationAbortSchema {
		if _, present := members[field]; present {
			return fmt.Errorf("legacy native abort review field forbidden")
		}
	}
	return nil
}

const (
	NativePreRegistrationAbortReviewedQuarantineSchema   = "native_pre_registration_abort_reviewed_quarantine_v2"
	NativePreRegistrationAbortReviewedQuarantineProtocol = "native_pre_registration_abort_reviewed_quarantine_original_v2"
)

// The legacy validator remains available to the original abort, recovery and
// quarantine contracts. Only this explicit manual entry accepts the new schema.
func ValidateNativeManualAbortBinding(policy model.Manifest, p model.CapacityPolicySpec, b model.CapacityNativeAbortBinding) error {
	if b.Schema == NativePreRegistrationAbortSchema {
		return ValidateNativeAbortBinding(policy, p, b)
	}
	if b.Schema != NativePreRegistrationAbortReviewedQuarantineSchema || b.ReviewedQuarantines == nil || len(b.ReviewedQuarantines.Receipts) < 1 || len(b.ReviewedQuarantines.Receipts) > 16 {
		return fmt.Errorf("explicit fixed reviewed-quarantine native abort required")
	}
	legacy := b
	legacy.Schema, legacy.ReviewedQuarantines = NativePreRegistrationAbortSchema, nil
	if ValidateNativeAbortBinding(policy, p, legacy) != nil {
		return fmt.Errorf("fixed reviewed-quarantine native target required")
	}
	previous := ""
	subjects := map[string]bool{}
	for _, ref := range b.ReviewedQuarantines.Receipts {
		if !NativeProcessNonce(ref.CommandID) || !NativeProcessNonce(ref.SubjectUID) || ref.CommandID <= previous || ref.SubjectUID == b.PodUID || subjects[ref.SubjectUID] || !nativeAbortHex(ref.RecordSHA256, 32) {
			return fmt.Errorf("ordered distinct different-UID quarantine references required")
		}
		previous, subjects[ref.SubjectUID] = ref.CommandID, true
	}
	return nil
}

func NativeManualAbortProtocol(schema string) string {
	switch schema {
	case NativePreRegistrationAbortSchema:
		return NativePreRegistrationAbortProtocol
	case NativePreRegistrationAbortReviewedQuarantineSchema:
		return NativePreRegistrationAbortReviewedQuarantineProtocol
	default:
		return ""
	}
}

func ValidateNativeManualAbortProof(policy model.Manifest, p model.CapacityPolicySpec, proof model.CapacityNativeAbortProof, now time.Time) error {
	if proof.Schema == NativePreRegistrationAbortSchema {
		return ValidateNativeAbortProof(policy, p, proof, now)
	}
	if ValidateNativeManualAbortBinding(policy, p, proof.Binding) != nil || proof.Schema != NativePreRegistrationAbortReviewedQuarantineSchema || proof.Binding.Schema != proof.Schema || proof.ReviewedQuarantineCounts == nil || proof.FencingToken < 1 || proof.AuthoredAt.IsZero() || !Fresh(proof.AuthoredAt, now, p.MaxEvidenceAgeSeconds) || proof.AuthoredAt.Before(proof.Observation.ObservedAt) || proof.ZeroHistory != (model.CapacityNativeAbortZeroHistory{}) || ValidateNativeAbortObservation(p, proof.Binding, proof.Observation, now, true) != nil {
		return fmt.Errorf("server-owned reviewed-quarantine native abort proof required")
	}
	n := int64(len(proof.Binding.ReviewedQuarantines.Receipts))
	if proof.ScopeUnsettledCommands != n || *proof.ReviewedQuarantineCounts != (model.CapacityNativeUnsettledCounts{RawUnsettled: n, Quarantined: n}) {
		return fmt.Errorf("honest reviewed raw quarantine counts required")
	}
	return nil
}
