package repository

import (
	"context"
	"database/sql"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// Strengthens only policies with the explicit new Notify canary contract.
// Generic workflows cannot turn healthy=true or a physical slot count into
// business readiness. Existing qualification and generic legacy paths remain.
func (s CapacityStore) guardGuestNotifyPhaseTx(ctx context.Context, tx *sql.Tx, policy model.Manifest, p model.CapacityPolicySpec, previous *model.CapacityIntent, next model.CapacityIntent, now time.Time) error {
	if p.GuestNotifyCanaryBinding == nil || previous == nil || next.Phase == previous.Phase || (next.Phase != "prepared" && next.Phase != "canary" && next.Phase != "promoted") {
		return nil
	}
	if next.Decision.Units < p.Floor || previous.RecoveryOnly || previous.FloorDegraded {
		return ErrCapacityConflict
	}
	usage := "initial_useful_membership"
	if capacityIntentReduction(*previous) {
		usage = "after_retirement_floor"
	}
	useful, err := s.guestNotifyUsefulMembersTx(ctx, tx, policy, p, *previous, 0, now, usage, time.Time{})
	if err != nil {
		return err
	}
	var live int
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_resource_slots WHERE NOT(slot_record ? 'authority_kind') AND namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 AND resource_id<>''`, policy.Metadata.Namespace, p.Environment, p.Domain, p.Dimension).Scan(&live); err != nil {
		return err
	}
	if useful != live || live != next.Decision.Units {
		return ErrCapacityConflict
	}
	return nil
}

func (s CapacityStore) guestNotifyRetirementFloorTx(ctx context.Context, tx *sql.Tx, policy model.Manifest, p model.CapacityPolicySpec, current model.CapacityIntent, slot int, now time.Time, usage, afterAckID string) error {
	if current.FailedInstalledDisposal != nil {
		valid, err := s.failedInstalledDisposalActiveTx(ctx, tx, policy, p, current, slot, now)
		if err != nil || !valid {
			return ErrCapacityConflict
		}
		return nil
	}
	if p.GuestNotifyCanaryBinding == nil {
		return nil
	}
	if current.FloorDegraded || current.RecoveryOnly {
		return ErrCapacityConflict
	}
	var afterPG time.Time
	if afterAckID != "" {
		// Native Core PG order proves this NEW canary was issued after the
		// original caller acknowledgement was durably retained. Guest wall time
		// cannot stand in for this source-owned execution order.
		if err := tx.QueryRowContext(ctx, `SELECT recorded_at FROM public.capacity_guest_original_caller_returns WHERE intent_id=$1 AND original_record->>'body_persisted'='true'`, afterAckID).Scan(&afterPG); err != nil {
			return ErrCapacityConflict
		}
	}
	useful, err := s.guestNotifyUsefulMembersTx(ctx, tx, policy, p, current, slot, now, usage, afterPG)
	if err != nil {
		return err
	}
	if useful < p.Floor || useful < current.Decision.Units {
		return ErrCapacityConflict
	}
	return nil
}
