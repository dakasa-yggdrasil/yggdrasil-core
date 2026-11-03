package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// AdvanceGuestRetirementDrainedV2 records completed withdrawal, quiescence and
// native poweroff before the ordinary destroy grant can be issued. It neither
// fabricates a reduced inventory assessment nor relaxes IssueMutation's gate.
func (s CapacityStore) AdvanceGuestRetirementDrainedV2(ctx context.Context, policy model.Manifest, generation, fence int64, owner, id, preregistrationID string, slot int) (model.CapacityIntent, error) {
	var out model.CapacityIntent
	origin := s.guestNotifyOrigin
	if s.DB == nil || !guestReconcileLive(ctx) || origin == nil || origin.source != capacity.CurrentGuestCoreSource() || origin.step.Use.Kind != "yggdrasil" || origin.step.Use.Operation != "capacity.finish_original_guest_retirement" {
		return out, ErrCapacityConflict
	}
	err := s.guestRetirementV2Transaction(ctx, id, true, func(tx *sql.Tx, stored GuestRetirementOriginalV2, now time.Time) error {
		actualPolicy, p, current, err := s.guestRetirementV2CurrentTx(ctx, tx, stored, now, false)
		if err != nil {
			return err
		}
		if actualPolicy.ID != policy.ID || actualPolicy.Checksum != policy.Checksum || stored.Request.Intent.PreregistrationID != preregistrationID || stored.Request.Intent.Slot != slot {
			return ErrCapacityConflict
		}
		// The finish invocation, not a public input or another executor, owns
		// the same original workflow step and immutable installed enrollment.
		if _, _, err = s.guestNotifyStoredTx(ctx, tx, policy, p, preregistrationID); err != nil {
			return err
		}
		b, err := capacity.VMObservationBinding(p, stored.Binding.MutationBindingName)
		if err != nil {
			return err
		}
		// Re-read the original signed five-row chain, closed caller return,
		// survivor floor and fresh native poweroff in this SAME transaction.
		if err = s.guestDestroyEligibilityV2Tx(ctx, tx, policy, p, current, b, slot, stored.Request.Intent.Tuple.ResourceID, stored.Request.Intent.Tuple.CreatedAt, now, "", id); err != nil {
			return err
		}
		out, err = s.guestRetirementDrainedV2State(policy, p, current, stored, generation, fence, owner, now)
		if err != nil || !guestReconcileLive(ctx) {
			return ErrCapacityConflict
		}
		return persistGuestRetirementDrainedV2Tx(ctx, tx, current, out, id)
	})
	return out, err
}

// State/CAS mechanics are separate from the original-evidence admission above.
// This private function grants no authority and performs no I/O.
func (s CapacityStore) guestRetirementDrainedV2State(policy model.Manifest, p model.CapacityPolicySpec, current model.CapacityIntent, stored GuestRetirementOriginalV2, generation, fence int64, owner string, now time.Time) (model.CapacityIntent, error) {
	i := stored.Request.Intent
	if err := s.checkLease(p, policy, &current, generation, fence, owner, now); err != nil {
		return model.CapacityIntent{}, err
	}
	if stored.ExecutorID != s.ExecutorID || i.PolicyID != policy.ID.String() || i.PolicyChecksum != policy.Checksum || i.WorkflowID != s.WorkflowID.String() || i.Generation != uint64(generation) || i.Fence != uint64(fence) || i.LeaseOwner != owner || !validCapacityExecutor(i.RequestID) || !validCapacityExecutor(i.PreregistrationID) || i.Slot < 1 || !capacityIntentReduction(current) || current.FailedInstalledDisposal != nil || (current.Phase != "draining" && current.Phase != "drained") {
		return model.CapacityIntent{}, ErrCapacityConflict
	}
	if current.Phase == "drained" {
		return current, nil
	}
	next := current
	next.Phase, next.UpdatedAt = "drained", now
	return next, nil
}

func persistGuestRetirementDrainedV2Tx(ctx context.Context, tx *sql.Tx, old, next model.CapacityIntent, id string) error {
	if old.Phase == "drained" {
		return nil
	}
	before, err := json.Marshal(old)
	if err != nil {
		return err
	}
	after, err := json.Marshal(next)
	if err != nil {
		return err
	}
	changed, err := tx.ExecContext(ctx, `UPDATE public.capacity_intents SET intent=$5::jsonb,updated_at=$7 WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 AND intent=$6::jsonb`, old.Namespace, old.Environment, old.Domain, old.Dimension, string(after), string(before), next.UpdatedAt)
	if err != nil {
		return err
	}
	n, err := changed.RowsAffected()
	if err != nil || n != 1 {
		return ErrCapacityConflict
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_intent_events(namespace,environment,domain,dimension,generation,fencing_token,phase,receipt_ref) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, next.Namespace, next.Environment, next.Domain, next.Dimension, next.Generation, next.FencingToken, next.Phase, "original-guest-retirement-v2:"+id+":drained")
	return err
}
