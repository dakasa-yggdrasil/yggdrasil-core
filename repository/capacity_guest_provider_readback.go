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

// Source-owned provider GET results are append-only, including historical
// accepted/uncertain writes. Retention alone never confirms or reclaims a slot.
func (s CapacityStore) RecordVMRetirementReadback(ctx context.Context, policy model.Manifest, generation, fence int64, owner string, observed model.CapacityVMRetirementObservation) error {
	return s.mutationTransaction(ctx, policy, true, generation, fence, owner, func(tx *sql.Tx, p model.CapacityPolicySpec, _ model.CapacityIntent, now time.Time) error {
		var raw []byte
		if err := tx.QueryRowContext(ctx, `SELECT grant_record FROM public.capacity_mutation_grants WHERE id=$1 AND namespace=$2 AND environment=$3 AND domain=$4 AND dimension=$5`, observed.DestroyGrantID, policy.Metadata.Namespace, p.Environment, p.Domain, p.Dimension).Scan(&raw); err != nil {
			return err
		}
		var original capacityMutationRecord
		if json.Unmarshal(raw, &original) != nil || original.WorkflowID != s.WorkflowID || original.Grant.Capability != original.Binding.DestroyCapability || original.Settlement == nil || observed.ID != original.Grant.ExpectedResourceID || observed.CreatedAt != original.Grant.ExpectedResourceCreatedAt || observed.DestroyGrantState != original.Grant.State || observed.OriginalOutcome != original.Settlement.Outcome || observed.OriginalTransportCompleted != original.Settlement.TransportCompleted {
			return ErrCapacityConflict
		}
		wire, err := json.Marshal(observed)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_vm_retirement_native_readbacks(id,destroy_grant_id,observation_sha256,original_observation_record,recorded_at,original_wire) VALUES($1,$2,$3,$4::jsonb,$5,$6) ON CONFLICT(destroy_grant_id,observation_sha256) DO NOTHING`, uuid.New(), original.Grant.GrantID, capacity.GuestRetirementSHA(observed), string(wire), now, wire)
		return err
	})
}

func (s CapacityStore) guestConfirmedDestroyTx(ctx context.Context, tx *sql.Tx, p model.CapacityPolicySpec, original capacityMutationRecord, proof model.CapacityMutationProof, now time.Time) error {
	if handled, err := s.canonicalSourceConfirmedCleanupTx(ctx, tx, p, original, proof, now); handled {
		return err
	}
	var id string
	var bindingWire []byte
	var digest string
	if err := tx.QueryRowContext(ctx, `SELECT intent_id::text,original_wire,eligibility_sha256 FROM public.capacity_vm_retirement_delete_bindings WHERE destroy_grant_id=$1`, original.Grant.GrantID).Scan(&id, &bindingWire, &digest); err != nil {
		return ErrCapacityConflict
	}
	v2, kindErr := guestRetirementV2KindTx(ctx, tx, id)
	if kindErr != nil {
		return kindErr
	}
	if v2 {
		return guestConfirmedDestroyV2Tx(ctx, tx, p, original, proof, now)
	}
	var eligibility model.CapacityGuestRetirementObservation
	if capacity.DecodeGuestLifecycle(bindingWire, &eligibility) != nil || capacity.GuestRetirementSHA(eligibility) != digest {
		return ErrCapacityConflict
	}
	stored, err := loadGuestRetirementTx(ctx, tx, id)
	if err != nil {
		return err
	}
	quiescent, err := guestQuiescentProofTx(ctx, tx, stored)
	if err != nil || !reflect.DeepEqual(quiescent, eligibility) || stored.Request.Intent.Tuple.ResourceID != original.Grant.ExpectedResourceID || stored.Request.Intent.Tuple.CreatedAt != original.Grant.ExpectedResourceCreatedAt || stored.Request.Intent.Tuple.InstanceID != original.Binding.IntegrationInstanceID || stored.Request.Intent.Tuple.ScopeChecksum != original.Binding.ScopeChecksum || stored.Request.Intent.Slot != original.Grant.Slot {
		return ErrCapacityConflict
	}
	var nativeWire []byte
	if err = tx.QueryRowContext(ctx, `SELECT original_wire FROM public.capacity_vm_retirement_native_readbacks WHERE destroy_grant_id=$1 ORDER BY recorded_at DESC LIMIT 1`, original.Grant.GrantID).Scan(&nativeWire); err != nil {
		return ErrCapacityConflict
	}
	var observed model.CapacityVMRetirementObservation
	if stored.Binding.EvidenceClass == "native_qemu_qualification" {
		var native GuestNativeQEMUDeleteReadback
		if capacity.DecodeGuestLifecycle(nativeWire, &native) != nil {
			return ErrCapacityConflict
		}
		creator, loadErr := guestNativeQEMUIdentityTx(ctx, tx, stored.Preregistration.PreregistrationID)
		if loadErr != nil || creator.OriginalCreatorSHA256 != native.OriginalDelete.CreatorOriginalSHA256 || creator.OriginalDisk != native.OriginalDelete.OriginalDisk {
			return ErrCapacityConflict
		}
		var offWire, joinWire []byte
		if tx.QueryRowContext(ctx, `SELECT original_wire,original_native_join_wire FROM public.capacity_guest_original_native_poweroff_reads WHERE intent_id=$1`, id).Scan(&offWire, &joinWire) != nil {
			return ErrCapacityConflict
		}
		var off GuestNativeQEMUOffReturn
		var join GuestNativeQEMUPIDFDReturn
		if capacity.DecodeGuestLifecycle(offWire, &off) != nil || capacity.DecodeGuestLifecycle(joinWire, &join) != nil || !guestNativeQEMUSameCreator(off, creator) || !guestNativeQEMUOffJoin(off, join, stored, quiescent, creator.OriginalCreatorSHA256, join.OriginalCloseReturnedAt) || native.OriginalDelete.OriginalUnlinkCalledAt.Before(join.OriginalCloseReturnedAt) {
			return ErrCapacityConflict
		}
		return guestNativeQEMUConfirmedDelete(p, original, stored, nativeWire, proof, now)
	}
	if capacity.DecodeVMObservation(json.RawMessage(nativeWire), &observed) != nil {
		return ErrCapacityConflict
	}
	r := model.CapacityMutationReceipt{Grant: original.Grant, AttemptID: original.AttemptID, Outcome: original.Settlement.Outcome, TransportCompleted: original.Settlement.TransportCompleted, ResourceID: original.Settlement.ResourceID, ResourceCreatedAt: original.Settlement.ResourceCreatedAt, ActionID: original.Settlement.ActionID, NextActionIDs: original.Settlement.NextActionIDs, AuxiliaryResources: original.Settlement.AuxiliaryResources, AuxiliaryInventoryComplete: original.Settlement.AuxiliaryInventoryComplete}
	expected, err := capacity.VMRetirementProof(p, original.Binding, r, observed, now, proof.ReceiptRef)
	if err != nil || !reflect.DeepEqual(expected, proof) {
		return ErrCapacityConflict
	}
	return nil
}
