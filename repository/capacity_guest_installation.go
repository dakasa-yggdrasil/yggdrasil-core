package repository

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"time"
)

// RegisterOriginalGuestInstallation never replaces an original. An exact repeat
// can resolve a lost reply while the SAME original remains current and in time.
func (s CapacityStore) RegisterOriginalGuestInstallation(ctx context.Context, principal string, confirmation model.CapacityGuestOriginalInstallationConfirmation) (model.CapacityGuestOriginalInstallationConfirmation, error) {
	var result model.CapacityGuestOriginalInstallationConfirmation
	err := s.guestStoredTransaction(ctx, confirmation.PreregistrationID, func(tx *sql.Tx, stored guestOriginalStored, now time.Time) error {
		if principal != stored.member.ProvisionerClientPrincipal {
			return ErrCapacityMutationAuthorization
		}
		if _, _, err := s.guestCurrentTx(ctx, tx, stored, now, true); err != nil {
			return err
		}
		receipt, _, err := loadGuestReceiptTx(ctx, tx, stored.pre.PreregistrationID)
		if err != nil {
			return err
		}
		result, err = storeGuestInstallationTx(ctx, tx, stored, receipt, confirmation, now)
		return err

	})
	return result, err
}

// GuestInstallationConfirmation is a current, original-deadline-bound barrier.
// sql.ErrNoRows means pending, not ready, and does not reserve a probe.
func (s CapacityStore) GuestInstallationConfirmation(ctx context.Context, principal, id, nonceSHA string) (model.CapacityGuestOriginalInstallationConfirmation, error) {
	var result model.CapacityGuestOriginalInstallationConfirmation
	err := s.guestStoredTransaction(ctx, id, func(tx *sql.Tx, stored guestOriginalStored, now time.Time) error {
		if principal != stored.member.ProvisionerClientPrincipal || nonceSHA != stored.pre.NonceSHA256 {
			return ErrCapacityMutationAuthorization
		}
		if _, _, err := s.guestCurrentTx(ctx, tx, stored, now, true); err != nil {
			return err
		}
		receipt, _, err := loadGuestReceiptTx(ctx, tx, id)
		if err != nil {
			return err
		}
		result, err = loadGuestInstallationTx(ctx, tx, stored, receipt)
		if err != nil {
			return err
		}

		return nil
	})
	return result, err
}

// A stored confirmation is authenticated at its original database record time;
// later probes still apply their own current policy/lease checks. This never
// extends the deadline for accepting a NEW installation confirmation.
func loadGuestInstallationTx(ctx context.Context, tx *sql.Tx, stored guestOriginalStored, receipt model.CapacityGuestOriginalProvisioningReceipt) (model.CapacityGuestOriginalInstallationConfirmation, error) {
	var result model.CapacityGuestOriginalInstallationConfirmation
	var wire []byte
	var digest string
	var recorded time.Time
	err := tx.QueryRowContext(ctx, `SELECT original_wire,confirmation_sha256,recorded_at FROM public.capacity_guest_original_installations WHERE preregistration_id=$1 FOR SHARE`, stored.pre.PreregistrationID).Scan(&wire, &digest, &recorded)
	if err != nil {
		return result, err
	}
	if capacity.DecodeGuestLifecycle(wire, &result) != nil || capacity.GuestRetirementSHA(result) != digest || capacity.GuestOriginalInstallation(stored.pre, receipt, result, stored.binding.ProvisionerPublicKey, recorded) != nil {
		return result, ErrCapacityConflict
	}
	canonical, err := json.Marshal(result)
	if err != nil || !bytes.Equal(canonical, wire) {
		return result, ErrCapacityConflict
	}
	return result, nil
}

func storeGuestInstallationTx(ctx context.Context, tx *sql.Tx, stored guestOriginalStored, receipt model.CapacityGuestOriginalProvisioningReceipt, confirmation model.CapacityGuestOriginalInstallationConfirmation, now time.Time) (model.CapacityGuestOriginalInstallationConfirmation, error) {
	var zero model.CapacityGuestOriginalInstallationConfirmation
	if capacity.GuestOriginalInstallation(stored.pre, receipt, confirmation, stored.binding.ProvisionerPublicKey, now) != nil {
		return zero, ErrCapacityConflict
	}
	wire, err := json.Marshal(confirmation)
	if err != nil {
		return zero, err
	}
	var old []byte
	err = tx.QueryRowContext(ctx, `SELECT original_wire FROM public.capacity_guest_original_installations WHERE preregistration_id=$1 FOR SHARE`, stored.pre.PreregistrationID).Scan(&old)
	if err == nil {
		if !bytes.Equal(old, wire) {
			return zero, ErrCapacityConflict
		}
		return confirmation, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return zero, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_guest_original_installations(preregistration_id,original_wire,confirmation_sha256,recorded_at) VALUES($1,$2,$3,$4)`, stored.pre.PreregistrationID, wire, capacity.GuestRetirementSHA(confirmation), now)
	if err != nil {
		return zero, err
	}
	return confirmation, nil
}
