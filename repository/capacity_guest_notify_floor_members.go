package repository

import (
	"context"
	"database/sql"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

type GuestNotifyFloorMember struct {
	Slot              int
	PreregistrationID string
}

// This only discovers actual surviving native/enrolled members. Each subsequent
// original publication/read independently rechecks current epoch and authority.
func (s CapacityStore) GuestNotifyFloorMembers(ctx context.Context, policy model.Manifest, generation, fence int64, owner string, excludedSlot int) ([]GuestNotifyFloorMember, error) {
	var out []GuestNotifyFloorMember
	err := s.mutationTransaction(ctx, policy, false, generation, fence, owner, func(tx *sql.Tx, p model.CapacityPolicySpec, current model.CapacityIntent, now time.Time) error {
		if s.guestNotifyOrigin == nil || s.guestNotifyOrigin.source != capacity.CurrentGuestCoreSource() || p.GuestNotifyCanaryBinding == nil || p.GuestRetirementBinding == nil || !capacityIntentReduction(current) || current.RecoveryOnly || current.FloorDegraded || (current.Phase != "draining" && current.Phase != "drained") {
			return ErrCapacityConflict
		}
		if current.FailedInstalledDisposal != nil {
			valid, err := s.failedInstalledDisposalActiveTx(ctx, tx, policy, p, current, excludedSlot, now)
			if err != nil || !valid {
				return ErrCapacityConflict
			}
			return nil
		}
		r := *p.GuestRetirementBinding
		b, err := capacity.VMObservationBinding(p, r.MutationBindingName)
		if err != nil || checkMutationIntegration(ctx, tx, b) != nil {
			return ErrCapacityConflict
		}
		provider := ""
		for _, profile := range p.Profiles {
			if profile.Name == b.ProfileName {
				provider = profile.Provider
			}
		}
		if !capacity.GuestOriginalProfileEnabled(p, r, provider) {
			return ErrCapacityConflict
		}
		for _, member := range r.Members {
			if member.Slot == excludedSlot {
				continue
			}
			slot, exists, err := loadMutationSlot(ctx, tx, policy.Metadata.Namespace, p, b, member.Slot)
			if err != nil {
				return err
			}
			if !exists || slot.Tombstone || slot.ResourceID == "" {
				continue
			}
			var pending int
			if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_mutation_grants WHERE NOT(grant_record ? 'authority_kind') AND namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 AND slot=$5 AND state IN ('issued','redeemed','settled','compensating') AND grant_record->'grant'->>'capability'=$6`, policy.Metadata.Namespace, p.Environment, p.Domain, p.Dimension, member.Slot, b.DestroyCapability).Scan(&pending); err != nil {
				return err
			}
			if pending != 0 {
				continue
			}
			receipt, err := guestNotifyMemberReceiptTx(ctx, tx, policy, p, member, slot)
			if err != nil {
				return err
			}
			if _, _, err = s.guestNotifyStoredTx(ctx, tx, policy, p, receipt.PreregistrationID); err != nil {
				return err
			}
			out = append(out, GuestNotifyFloorMember{member.Slot, receipt.PreregistrationID})
		}
		if len(out) < p.Floor || len(out) < current.Decision.Units {
			return ErrCapacityConflict
		}
		return nil
	})
	return out, err
}
