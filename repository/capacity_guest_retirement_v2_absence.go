package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"reflect"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

type GuestNativeAbsenceReturnV2 struct {
	Schema                       string                                 `json:"schema"`
	Challenge                    GuestNativePoweroffReadV2              `json:"challenge"`
	DestroyGrantID               string                                 `json:"destroy_grant_id"`
	OriginalDestroyReceiptSHA256 string                                 `json:"original_destroy_receipt_sha256"`
	Status                       string                                 `json:"status"`
	Observation                  *model.CapacityVMRetirementObservation `json:"observation,omitempty"`
	StartedAtCore                time.Time                              `json:"started_at_core"`
	OriginalReturnedAtCore       time.Time                              `json:"original_returned_at_core"`
	CallFailed                   bool                                   `json:"call_failed"`
	OriginalContextFailed        bool                                   `json:"original_context_failed"`
}

func guestMutationReceiptV2(r capacityMutationRecord) model.CapacityMutationReceipt {
	out := model.CapacityMutationReceipt{Grant: r.Grant, AttemptID: r.AttemptID}
	if r.Settlement != nil {
		x := r.Settlement
		out.Outcome = x.Outcome
		out.TransportCompleted = x.TransportCompleted
		out.ResourceID = x.ResourceID
		out.ResourceCreatedAt = x.ResourceCreatedAt
		out.ActionID = x.ActionID
		out.NextActionIDs = x.NextActionIDs
		out.AuxiliaryResources = x.AuxiliaryResources
		out.AuxiliaryInventoryComplete = x.AuxiliaryInventoryComplete
	}
	return out
}

func guestNativeAbsenceContentV2(r GuestNativeAbsenceReturnV2, p model.CapacityPolicySpec, original capacityMutationRecord) (model.CapacityMutationProof, error) {
	c := r.Challenge
	g := original.Grant
	b := original.Binding
	if r.Schema != "original_core_guest_native_absence_return_v2" || r.Status != "observed" || r.Observation == nil || r.CallFailed || r.OriginalContextFailed || c.Schema != "original_core_guest_native_poweroff_read_challenge_v2" || !validCapacityExecutor(c.ReadID) || !validCapacityExecutor(c.IntentID) || !capacity.ValidDigest(c.IntentSHA256) || !capacity.ValidDigest(c.OriginalCallerSHA256) || c.MutationBindingSHA256 != capacity.GuestRetirementSHA(b) || c.AdapterSourceCommit != b.OriginalProviderSourceCommit || c.Tuple.ResourceID != g.ExpectedResourceID || c.Tuple.CreatedAt != g.ExpectedResourceCreatedAt || c.IssuedAtCore.IsZero() || !c.OriginalDeadlineCore.After(c.IssuedAtCore) || c.OriginalDeadlineCore.Sub(c.IssuedAtCore) > 5*time.Second || r.StartedAtCore.Before(c.IssuedAtCore) || r.OriginalReturnedAtCore.Before(r.StartedAtCore) || !r.OriginalReturnedAtCore.Before(c.OriginalDeadlineCore) || r.DestroyGrantID != g.GrantID || r.OriginalDestroyReceiptSHA256 != capacity.GuestRetirementSHA(guestMutationReceiptV2(original)) || original.Settlement == nil || g.State != "settled" || !original.Settlement.TransportCompleted || original.Settlement.Outcome != "accepted" {
		return model.CapacityMutationProof{}, ErrCapacityConflict
	}
	if capacity.AWSOriginalMutationPair(b) {
		x := original.Settlement.OriginalProviderDestroyReturn
		if x == nil || original.Settlement.OriginalProviderCreateReturn != nil || x.Schema != "aws_original_terminate_instances_return_v1" || x.Provider != "aws" || x.AdapterSourceCommit != b.OriginalProviderSourceCommit || x.GrantID != g.GrantID || x.AttemptID != original.AttemptID || x.RequestSHA256 != g.RequestSHA256 || x.ResourceID != g.ExpectedResourceID || x.ResourceCreatedAt != g.ExpectedResourceCreatedAt || x.ActionID != original.Settlement.ActionID || x.NextActionIDs == nil || len(x.NextActionIDs) != 0 || x.ResponseStatus != 200 || !capacity.ValidDigest(x.ResponseBodySHA256) || x.ResponseBytes < 2 || x.ResponseBytes > 2<<20 {
			return model.CapacityMutationProof{}, ErrCapacityConflict
		}
		called, a := time.Parse(time.RFC3339Nano, x.CalledAt)
		returned, z := time.Parse(time.RFC3339Nano, x.ReturnedAt)
		deadline, d := time.Parse(time.RFC3339Nano, x.ContextDeadline)
		if a != nil || z != nil || d != nil || called.IsZero() || returned.Before(called) || !returned.Before(deadline) || deadline.Sub(called) > 60*time.Second || called.UTC().Format(time.RFC3339Nano) != x.CalledAt || returned.UTC().Format(time.RFC3339Nano) != x.ReturnedAt || deadline.UTC().Format(time.RFC3339Nano) != x.ContextDeadline {
			return model.CapacityMutationProof{}, ErrCapacityConflict
		}
	}
	return capacity.GuestRetirementV2NativeAbsenceContent(p, b, guestMutationReceiptV2(original), *r.Observation, "original-core-v2-native-absence:"+c.ReadID)
}

// Original native timestamps stay inside the immutable source return. The
// resulting proof's ObservedAt is explicitly the actual Core PG custody time;
// it is never copied into the provider return or presented as a native stamp.
func (s CapacityStore) RecordGuestNativeAbsenceV2(ctx context.Context, r GuestNativeAbsenceReturnV2) (model.CapacityMutationProof, error) {
	var proof model.CapacityMutationProof
	accepted := false
	err := s.guestRetirementV2Transaction(ctx, r.Challenge.IntentID, true, func(tx *sql.Tx, stored GuestRetirementOriginalV2, now time.Time) error {
		_, p, _, err := s.guestRetirementV2CurrentTx(ctx, tx, stored, now, false)
		if err != nil {
			return err
		}
		if _, err = guestQuiescentProofV2Tx(ctx, tx, stored); err != nil {
			return err
		}
		var wire, challengeWire []byte
		var digest string
		var consistent bool
		if tx.QueryRowContext(ctx, `SELECT original_wire,observation_sha256,original_record=convert_from(original_wire,'UTF8')::jsonb FROM public.capacity_guest_original_native_poweroff_reads WHERE id=$1 AND intent_id=$2`, r.Challenge.ReadID, r.Challenge.IntentID).Scan(&challengeWire, &digest, &consistent) != nil {
			return ErrCapacityConflict
		}
		var challenge GuestNativePoweroffReadV2
		if !consistent || capacity.DecodeGuestLifecycle(challengeWire, &challenge) != nil || capacity.GuestRetirementSHA(challenge) != digest || !reflect.DeepEqual(challenge, r.Challenge) || challenge.IntentSHA256 != capacity.GuestRetirementSHA(stored.Request.Intent) || challenge.Tuple != stored.Request.Intent.Tuple {
			return ErrCapacityConflict
		}
		if tx.QueryRowContext(ctx, `SELECT grant_record FROM public.capacity_mutation_grants WHERE id=$1`, r.DestroyGrantID).Scan(&wire) != nil {
			return ErrCapacityConflict
		}
		var original capacityMutationRecord
		if json.Unmarshal(wire, &original) != nil || original.WorkflowID != s.WorkflowID || original.PolicyID.String() != stored.Request.Intent.PolicyID || original.PolicyChecksum != stored.Request.Intent.PolicyChecksum {
			return ErrCapacityConflict
		}
		if _, err = guestDestroyEligibilityRecordV2ForGrantTx(ctx, tx, original); err != nil {
			return err
		}
		proof, err = guestNativeAbsenceContentV2(r, p, original)
		accepted = err == nil
		if !accepted {
			r.Observation = nil
		}
		raw, err := json.Marshal(r)
		if err != nil || len(raw) > 1<<20 {
			return ErrCapacityConflict
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_vm_retirement_native_readbacks(id,destroy_grant_id,observation_sha256,original_observation_record,recorded_at,original_wire) VALUES($1,$2,$3,$4::jsonb,$5,$6) ON CONFLICT(destroy_grant_id,observation_sha256) DO NOTHING`, uuid.New(), r.DestroyGrantID, capacity.GuestRetirementSHA(r), string(raw), now, raw); err != nil {
			return err
		}
		if accepted {
			proof.ObservedAt = now
		}
		return nil
	})
	if err != nil {
		return proof, err
	}
	if !accepted {
		return proof, ErrCapacityConflict
	}
	return proof, nil
}

func guestDestroyEligibilityRecordV2ForGrantTx(ctx context.Context, tx *sql.Tx, original capacityMutationRecord) (GuestRetirementOriginalV2, error) {
	var id, digest string
	var wire []byte
	if err := tx.QueryRowContext(ctx, `SELECT intent_id::text,original_wire,eligibility_sha256 FROM public.capacity_vm_retirement_delete_bindings WHERE destroy_grant_id=$1`, original.Grant.GrantID).Scan(&id, &wire, &digest); err != nil {
		return GuestRetirementOriginalV2{}, ErrCapacityConflict
	}
	return guestDestroyEligibilityRecordV2Tx(ctx, tx, original, id, wire, digest)
}

func guestConfirmedDestroyV2Tx(ctx context.Context, tx *sql.Tx, p model.CapacityPolicySpec, original capacityMutationRecord, proof model.CapacityMutationProof, now time.Time) error {
	stored, err := guestDestroyEligibilityRecordV2ForGrantTx(ctx, tx, original)
	if err != nil {
		return err
	}
	var raw []byte
	var digest string
	var recorded time.Time
	var consistent bool
	if tx.QueryRowContext(ctx, `SELECT original_wire,observation_sha256,recorded_at,original_observation_record=convert_from(original_wire,'UTF8')::jsonb FROM public.capacity_vm_retirement_native_readbacks WHERE destroy_grant_id=$1 AND original_observation_record->>'schema'='original_core_guest_native_absence_return_v2' ORDER BY recorded_at DESC,id DESC LIMIT 1`, original.Grant.GrantID).Scan(&raw, &digest, &recorded, &consistent) != nil {
		return ErrCapacityConflict
	}
	var returned GuestNativeAbsenceReturnV2
	if !consistent || capacity.DecodeGuestLifecycle(raw, &returned) != nil || capacity.GuestRetirementSHA(returned) != digest || returned.Challenge.IntentID != stored.Request.Intent.RequestID || returned.Challenge.IntentSHA256 != capacity.GuestRetirementSHA(stored.Request.Intent) || returned.Challenge.Tuple != stored.Request.Intent.Tuple {
		return ErrCapacityConflict
	}
	var challengeRaw []byte
	var issued, ack time.Time
	if tx.QueryRowContext(ctx, `SELECT r.original_wire,r.recorded_at,c.recorded_at FROM public.capacity_guest_original_native_poweroff_reads r JOIN public.capacity_guest_original_caller_returns c ON c.intent_id=r.intent_id AND c.return_sha256=$3 WHERE r.id=$1 AND r.intent_id=$2`, returned.Challenge.ReadID, stored.Request.Intent.RequestID, returned.Challenge.OriginalCallerSHA256).Scan(&challengeRaw, &issued, &ack) != nil || !issued.After(ack) || recorded.Before(issued) {
		return ErrCapacityConflict
	}
	var challenge GuestNativePoweroffReadV2
	if capacity.DecodeGuestLifecycle(challengeRaw, &challenge) != nil || !reflect.DeepEqual(challenge, returned.Challenge) {
		return ErrCapacityConflict
	}
	age := now.Sub(issued)
	if age < 0 || age+5*time.Second > time.Duration(p.MaxEvidenceAgeSeconds)*time.Second {
		return ErrCapacityConflict
	}
	expected, err := guestNativeAbsenceContentV2(returned, p, original)
	if err != nil {
		return err
	}
	expected.ObservedAt = recorded
	if !reflect.DeepEqual(expected, proof) {
		return ErrCapacityConflict
	}
	return nil
}

// Only the exact V2 delete binding selects the causal read-custody validator.
// Every legacy/create/qualification grant retains its original validator.
func guestV2RetirementProofTx(ctx context.Context, tx *sql.Tx, p model.CapacityPolicySpec, original capacityMutationRecord, proof model.CapacityMutationProof, now time.Time) (bool, error) {
	if original.Grant.Capability != original.Binding.DestroyCapability || original.Grant.CompensationOf != "" {
		return false, nil
	}
	var schema string
	err := tx.QueryRowContext(ctx, `SELECT r.intent_record->>'schema' FROM public.capacity_vm_retirement_delete_bindings b JOIN public.capacity_vm_retirement_intents r ON r.id=b.intent_id WHERE b.destroy_grant_id=$1`, original.Grant.GrantID).Scan(&schema)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if schema != capacity.GuestRetirementV2IntentSchema {
		return false, nil
	}
	return true, guestConfirmedDestroyV2Tx(ctx, tx, p, original, proof, now)
}
