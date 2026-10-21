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

type GuestNativePoweroffReadV2 struct {
	Schema                string                         `json:"schema"`
	ReadID                string                         `json:"read_id"`
	IntentSHA256          string                         `json:"intent_sha256"`
	IntentID              string                         `json:"intent_id"`
	OriginalCallerSHA256  string                         `json:"original_caller_sha256"`
	MutationBindingSHA256 string                         `json:"mutation_binding_sha256"`
	AdapterSourceCommit   string                         `json:"adapter_source_commit"`
	Tuple                 model.CapacityGuestNativeTuple `json:"tuple"`
	IssuedAtCore          time.Time                      `json:"issued_at_core"`
	OriginalDeadlineCore  time.Time                      `json:"original_deadline_core"`
}

type GuestNativePoweroffReturnV2 struct {
	Schema                 string                     `json:"schema"`
	Challenge              GuestNativePoweroffReadV2  `json:"challenge"`
	Status                 string                     `json:"status"`
	Plan                   *model.CapacityVMFleetPlan `json:"plan,omitempty"`
	StartedAtCore          time.Time                  `json:"started_at_core"`
	OriginalReturnedAtCore time.Time                  `json:"original_returned_at_core"`
	CallFailed             bool                       `json:"call_failed"`
	OriginalContextFailed  bool                       `json:"original_context_failed"`
}

// A new read challenge is durably committed AFTER complete original quiescence
// and caller acknowledgement and BEFORE the one actual native provider read.
// Read-only observation never substitutes for that original success.
func (s CapacityStore) PrepareGuestNativePoweroffReadV2(ctx context.Context, id string) (GuestNativePoweroffReadV2, error) {
	var out GuestNativePoweroffReadV2
	err := s.guestRetirementV2Transaction(ctx, id, true, func(tx *sql.Tx, stored GuestRetirementOriginalV2, nowPG time.Time) error {
		_, p, current, err := s.guestRetirementV2CurrentTx(ctx, tx, stored, nowPG, false)
		if err != nil {
			return err
		}
		if _, err = guestQuiescentProofV2Tx(ctx, tx, stored); err != nil {
			return err
		}
		b, err := capacity.VMObservationBinding(p, stored.Binding.MutationBindingName)
		if err != nil {
			return err
		}
		deadline, ok := ctx.Deadline()
		if !ok || ctx.Err() != nil || current.LeaseExpiresAt == nil {
			return ErrCapacityConflict
		}
		sampleStarted := time.Now()
		var leaseNow time.Time
		if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&leaseNow); err != nil {
			return err
		}
		issued := time.Now()
		budget := min(5*time.Second, deadline.Sub(issued), current.LeaseExpiresAt.Sub(leaseNow)-issued.Sub(sampleStarted))
		if budget <= 0 {
			return ErrCapacityLease
		}
		var callerSHA string
		if err = tx.QueryRowContext(ctx, `SELECT return_sha256 FROM public.capacity_guest_original_caller_returns WHERE intent_id=$1 AND original_record->>'body_persisted'='true'`, id).Scan(&callerSHA); err != nil {
			return ErrCapacityConflict
		}
		out = GuestNativePoweroffReadV2{Schema: "original_core_guest_native_poweroff_read_challenge_v2", ReadID: uuid.NewString(), IntentSHA256: capacity.GuestRetirementSHA(stored.Request.Intent), IntentID: id, OriginalCallerSHA256: callerSHA, MutationBindingSHA256: capacity.GuestRetirementSHA(b), AdapterSourceCommit: b.OriginalProviderSourceCommit, Tuple: stored.Request.Intent.Tuple, IssuedAtCore: issued.UTC(), OriginalDeadlineCore: issued.Add(budget).UTC()}
		wire, err := json.Marshal(out)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_guest_original_native_poweroff_reads(id,intent_id,observation_sha256,original_wire,original_record,recorded_at) VALUES($1,$2,$3,$4,$5::jsonb,$6)`, out.ReadID, id, capacity.GuestRetirementSHA(out), wire, string(wire), nowPG)
		return err
	})
	return out, err
}

func guestNativePoweroffReadV2Content(r GuestNativePoweroffReturnV2, p model.CapacityPolicySpec, b model.CapacityMutationBinding, original model.CapacityMutationReceipt) bool {
	c := r.Challenge
	if r.Schema != "original_core_guest_native_poweroff_read_return_v2" || r.Plan == nil || r.Status != "observed" || r.CallFailed || r.OriginalContextFailed || c.Schema != "original_core_guest_native_poweroff_read_challenge_v2" || !validCapacityExecutor(c.ReadID) || !validCapacityExecutor(c.IntentID) || !capacity.ValidDigest(c.IntentSHA256) || !capacity.ValidDigest(c.OriginalCallerSHA256) || c.MutationBindingSHA256 != capacity.GuestRetirementSHA(b) || c.AdapterSourceCommit != b.OriginalProviderSourceCommit || c.IssuedAtCore.IsZero() || !c.OriginalDeadlineCore.After(c.IssuedAtCore) || c.OriginalDeadlineCore.Sub(c.IssuedAtCore) > 5*time.Second || r.StartedAtCore.Before(c.IssuedAtCore) || r.OriginalReturnedAtCore.Before(r.StartedAtCore) || !r.OriginalReturnedAtCore.Before(c.OriginalDeadlineCore) || r.Plan.Server == nil || r.Plan.Server.ID != c.Tuple.ResourceID || r.Plan.Server.CreatedAt != c.Tuple.CreatedAt {
		return false
	}
	return capacity.GuestRetirementV2NativeOffPlanContent(p, b, *r.Plan, original) == nil
}

func guestOriginalCreateReceiptV2Tx(ctx context.Context, tx *sql.Tx, stored GuestRetirementOriginalV2) (model.CapacityMutationReceipt, error) {
	var wire []byte
	var out model.CapacityMutationReceipt
	if err := tx.QueryRowContext(ctx, `SELECT grant_record FROM public.capacity_mutation_grants WHERE id=$1`, stored.Preregistration.OriginalCreateGrantID).Scan(&wire); err != nil {
		return out, err
	}
	var record capacityMutationRecord
	if json.Unmarshal(wire, &record) != nil || record.Settlement == nil || record.Grant.GrantID != stored.Preregistration.OriginalCreateGrantID {
		return out, ErrCapacityConflict
	}
	out = model.CapacityMutationReceipt{Grant: record.Grant, AttemptID: record.AttemptID, Outcome: record.Settlement.Outcome, TransportCompleted: record.Settlement.TransportCompleted, ResourceID: record.Settlement.ResourceID, ResourceCreatedAt: record.Settlement.ResourceCreatedAt, ActionID: record.Settlement.ActionID, NextActionIDs: record.Settlement.NextActionIDs, AuxiliaryResources: record.Settlement.AuxiliaryResources, AuxiliaryInventoryComplete: record.Settlement.AuxiliaryInventoryComplete}
	return out, nil
}

func (s CapacityStore) RecordGuestNativePoweroffV2(ctx context.Context, returned GuestNativePoweroffReturnV2) error {
	accepted := false
	err := s.guestRetirementV2Transaction(ctx, returned.Challenge.IntentID, true, func(tx *sql.Tx, stored GuestRetirementOriginalV2, nowPG time.Time) error {
		_, p, _, err := s.guestRetirementV2CurrentTx(ctx, tx, stored, nowPG, false)
		if err != nil {
			return err
		}
		if _, err = guestQuiescentProofV2Tx(ctx, tx, stored); err != nil {
			return err
		}
		b, err := capacity.VMObservationBinding(p, stored.Binding.MutationBindingName)
		if err != nil {
			return err
		}
		var wire []byte
		var digest string
		var consistent bool
		if err = tx.QueryRowContext(ctx, `SELECT original_wire,observation_sha256,original_record=convert_from(original_wire,'UTF8')::jsonb FROM public.capacity_guest_original_native_poweroff_reads WHERE id=$1 AND intent_id=$2`, returned.Challenge.ReadID, stored.Request.Intent.RequestID).Scan(&wire, &digest, &consistent); err != nil {
			return ErrCapacityConflict
		}
		var challenge GuestNativePoweroffReadV2
		if !consistent || capacity.DecodeGuestLifecycle(wire, &challenge) != nil || capacity.GuestRetirementSHA(challenge) != digest || !reflect.DeepEqual(challenge, returned.Challenge) || challenge.IntentSHA256 != capacity.GuestRetirementSHA(stored.Request.Intent) || challenge.Tuple != stored.Request.Intent.Tuple {
			return ErrCapacityConflict
		}
		original, err := guestOriginalCreateReceiptV2Tx(ctx, tx, stored)
		if err != nil {
			return err
		}
		accepted = guestNativePoweroffReadV2Content(returned, p, b, original)
		if !accepted {
			returned.Plan = nil
		} // unknown data never becomes retained proof.
		raw, err := json.Marshal(returned)
		if err != nil || len(raw) > 1<<20 {
			return ErrCapacityConflict
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_guest_original_native_poweroff_reads(id,intent_id,observation_sha256,original_wire,original_record,original_native_join_wire,recorded_at) VALUES($1,$2,$3,$4,$5::jsonb,$6,$7)`, uuid.New(), stored.Request.Intent.RequestID, capacity.GuestRetirementSHA(returned), raw, string(raw), wire, nowPG)
		return err
	})
	if err != nil {
		return err
	}
	if !accepted {
		return ErrCapacityConflict
	}
	return nil
}

func guestNativePoweroffV2Tx(ctx context.Context, tx *sql.Tx, stored GuestRetirementOriginalV2, p model.CapacityPolicySpec, b model.CapacityMutationBinding, nowPG time.Time) error {
	var raw, challengeWire []byte
	var recorded time.Time
	var digest string
	var consistent bool
	if err := tx.QueryRowContext(ctx, `SELECT original_wire,original_native_join_wire,observation_sha256,recorded_at,original_record=convert_from(original_wire,'UTF8')::jsonb FROM public.capacity_guest_original_native_poweroff_reads WHERE intent_id=$1 AND original_record->>'schema'='original_core_guest_native_poweroff_read_return_v2' ORDER BY recorded_at DESC,id DESC LIMIT 1`, stored.Request.Intent.RequestID).Scan(&raw, &challengeWire, &digest, &recorded, &consistent); err != nil {
		return ErrCapacityConflict
	}
	var returned GuestNativePoweroffReturnV2
	var challenge GuestNativePoweroffReadV2
	if !consistent || capacity.DecodeGuestLifecycle(raw, &returned) != nil || capacity.DecodeGuestLifecycle(challengeWire, &challenge) != nil || capacity.GuestRetirementSHA(returned) != digest || !reflect.DeepEqual(challenge, returned.Challenge) || challenge.IntentID != stored.Request.Intent.RequestID || challenge.IntentSHA256 != capacity.GuestRetirementSHA(stored.Request.Intent) || challenge.Tuple != stored.Request.Intent.Tuple {
		return ErrCapacityConflict
	}
	var originalWire []byte
	var issuedPG, ackPG time.Time
	if err := tx.QueryRowContext(ctx, `SELECT r.original_wire,r.recorded_at,c.recorded_at FROM public.capacity_guest_original_native_poweroff_reads r JOIN public.capacity_guest_original_caller_returns c ON c.intent_id=r.intent_id AND c.return_sha256=$3 WHERE r.id=$1 AND r.intent_id=$2`, challenge.ReadID, challenge.IntentID, challenge.OriginalCallerSHA256).Scan(&originalWire, &issuedPG, &ackPG); err != nil || !reflect.DeepEqual(originalWire, challengeWire) || !issuedPG.After(ackPG) {
		return ErrCapacityConflict
	}
	age := nowPG.Sub(issuedPG)
	if age < 0 || recorded.Before(issuedPG) || age+5*time.Second > time.Duration(p.MaxEvidenceAgeSeconds)*time.Second {
		return ErrCapacityConflict
	}
	original, err := guestOriginalCreateReceiptV2Tx(ctx, tx, stored)
	if err != nil || !guestNativePoweroffReadV2Content(returned, p, b, original) {
		return ErrCapacityConflict
	}
	return nil
}
