package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"reflect"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// The workflow supplies only an exact request reference. All authority is read
// from its immutable source records and the current protected workflow epoch.
func (s CapacityStore) GuestRetirementWorkflowOriginalV2(ctx context.Context, policy model.Manifest, generation, fence int64, owner, id, preregistrationID string, slot int) (GuestRetirementOriginalV2, error) {
	var out GuestRetirementOriginalV2
	err := s.guestRetirementV2Transaction(ctx, id, true, func(tx *sql.Tx, stored GuestRetirementOriginalV2, now time.Time) error {
		i := stored.Request.Intent
		if i.PolicyID != policy.ID.String() || i.PolicyChecksum != policy.Checksum || i.WorkflowID != s.WorkflowID.String() || generation < 1 || fence < 1 || i.Generation != uint64(generation) || i.Fence != uint64(fence) || i.LeaseOwner != owner || i.PreregistrationID != preregistrationID || i.Slot != slot {
			return ErrCapacityConflict
		}
		if _, _, _, err := s.guestRetirementV2CurrentTx(ctx, tx, stored, now, false); err != nil {
			return err
		}
		if _, err := guestQuiescentProofV2Tx(ctx, tx, stored); err != nil {
			return err
		}
		out = stored
		return nil
	})
	return out, err
}

func (s CapacityStore) guestDestroyEligibilityV2Tx(ctx context.Context, tx *sql.Tx, policy model.Manifest, p model.CapacityPolicySpec, current model.CapacityIntent, b model.CapacityMutationBinding, slot int, resourceID, created string, now time.Time, destroyGrantID, id string) error {
	stored, err := loadGuestRetirementV2Tx(ctx, tx, id, true)
	if err != nil {
		return err
	}
	i := stored.Request.Intent
	if i.PolicyID != policy.ID.String() || i.PolicyChecksum != policy.Checksum || i.WorkflowID != s.WorkflowID.String() || current.Generation < 1 || current.FencingToken < 1 || i.Generation != uint64(current.Generation) || i.Fence != uint64(current.FencingToken) || i.LeaseOwner != current.LeaseOwner || i.Slot != slot || i.Tuple.ResourceID != resourceID || i.Tuple.CreatedAt != created || i.Tuple.InstanceID != b.IntegrationInstanceID || i.Tuple.ScopeChecksum != b.ScopeChecksum {
		return ErrCapacityConflict
	}
	if _, _, _, err = s.guestRetirementV2CurrentTx(ctx, tx, stored, now, false); err != nil {
		return err
	}
	if _, err = guestQuiescentProofV2Tx(ctx, tx, stored); err != nil {
		return err
	}
	if err = s.guestNotifyRetirementFloorTx(ctx, tx, policy, p, current, slot, now, "after_retirement_floor", id); err != nil {
		return err
	}
	if err = guestNativePoweroffV2Tx(ctx, tx, stored, p, b, now); err != nil {
		return err
	}
	if destroyGrantID != "" {
		var linked string
		if tx.QueryRowContext(ctx, `SELECT intent_id::text FROM public.capacity_vm_retirement_delete_bindings WHERE destroy_grant_id=$1`, destroyGrantID).Scan(&linked) != nil || linked != id {
			return ErrCapacityConflict
		}
	}
	return nil
}

func bindGuestDestroyV2Tx(ctx context.Context, tx *sql.Tx, original capacityMutationRecord, now time.Time, id string) error {
	stored, err := loadGuestRetirementV2Tx(ctx, tx, id, true)
	if err != nil {
		return err
	}
	proof, err := guestQuiescentProofV2Tx(ctx, tx, stored)
	if err != nil {
		return err
	}
	i := stored.Request.Intent
	g := original.Grant
	if i.PolicyID != original.PolicyID.String() || i.PolicyChecksum != original.PolicyChecksum || i.WorkflowID != original.WorkflowID.String() || i.Slot != g.Slot || i.Tuple.ResourceID != g.ExpectedResourceID || i.Tuple.CreatedAt != g.ExpectedResourceCreatedAt || i.Tuple.InstanceID != original.Binding.IntegrationInstanceID || i.Tuple.ScopeChecksum != original.Binding.ScopeChecksum {
		return ErrCapacityConflict
	}
	raw, err := json.Marshal(proof)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_vm_retirement_delete_bindings(destroy_grant_id,intent_id,eligibility_sha256,original_eligibility_record,recorded_at,original_wire) VALUES($1,$2,$3,$4::jsonb,$5,$6)`, g.GrantID, id, capacity.GuestRetirementSHA(proof), string(raw), now, raw)
	return err
}

func guestDestroyEligibilityRecordV2Tx(ctx context.Context, tx *sql.Tx, original capacityMutationRecord, id string, wire []byte, digest string) (GuestRetirementOriginalV2, error) {
	stored, err := loadGuestRetirementV2Tx(ctx, tx, id, true)
	if err != nil {
		return stored, err
	}
	var eligibility model.CapacityGuestRetirementObservationV2
	if capacity.DecodeGuestLifecycle(wire, &eligibility) != nil || capacity.GuestRetirementSHA(eligibility) != digest {
		return stored, ErrCapacityConflict
	}
	quiescent, err := guestQuiescentProofV2Tx(ctx, tx, stored)
	if err != nil || !reflect.DeepEqual(quiescent, eligibility) || stored.Request.Intent.Tuple.ResourceID != original.Grant.ExpectedResourceID || stored.Request.Intent.Tuple.CreatedAt != original.Grant.ExpectedResourceCreatedAt || stored.Request.Intent.Tuple.InstanceID != original.Binding.IntegrationInstanceID || stored.Request.Intent.Tuple.ScopeChecksum != original.Binding.ScopeChecksum || stored.Request.Intent.Slot != original.Grant.Slot {
		return stored, ErrCapacityConflict
	}
	return stored, nil
}

// A durable prior binding permits GET-only reconciliation, never a second
// issuance/send. Unknown originals remain held under their exact grant ID.
func (s CapacityStore) GuestRetirementDestroyReceiptV2(ctx context.Context, id string) (model.CapacityMutationReceipt, bool, error) {
	var out model.CapacityMutationReceipt
	found := false
	err := s.guestRetirementV2Transaction(ctx, id, true, func(tx *sql.Tx, stored GuestRetirementOriginalV2, now time.Time) error {
		if _, _, _, err := s.guestRetirementV2CurrentTx(ctx, tx, stored, now, false); err != nil {
			return err
		}
		var raw []byte
		err := tx.QueryRowContext(ctx, `SELECT g.grant_record FROM public.capacity_vm_retirement_delete_bindings b JOIN public.capacity_mutation_grants g ON g.id=b.destroy_grant_id WHERE b.intent_id=$1`, id).Scan(&raw)
		if err == sql.ErrNoRows {
			return nil
		}
		if err != nil {
			return err
		}
		var original capacityMutationRecord
		if json.Unmarshal(raw, &original) != nil || original.WorkflowID != s.WorkflowID || original.PolicyID.String() != stored.Request.Intent.PolicyID || original.PolicyChecksum != stored.Request.Intent.PolicyChecksum {
			return ErrCapacityConflict
		}
		if _, err = guestDestroyEligibilityRecordV2ForGrantTx(ctx, tx, original); err != nil {
			return err
		}
		out = guestMutationReceiptV2(original)
		found = true
		return nil
	})
	return out, found, err
}
