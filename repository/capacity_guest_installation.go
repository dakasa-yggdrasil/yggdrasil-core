package repository

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
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
		p, _, err := s.guestCurrentTx(ctx, tx, stored, now, true)
		if err != nil {
			return err
		}
		receipt, _, err := loadGuestReceiptTx(ctx, tx, stored.pre.PreregistrationID)
		if err != nil {
			return err
		}
		result, err = storeGuestInstallationTx(ctx, tx, stored, receipt, confirmation, now, func() error {
			issuer := s
			issuer.WorkflowID = uuid.MustParse(stored.pre.WorkflowID)
			issuer.ExecutorID = stored.pre.ExecutorID
			return issuer.recordGuestAuthorityIssueTx(ctx, tx, model.Manifest{ID: uuid.MustParse(stored.pre.PolicyID)}, p, stored.binding, "installation", stored.pre.PreregistrationID, capacity.GuestRetirementSHA(confirmation))
		})
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
		if _, _, currentErr := s.guestCurrentTx(ctx, tx, stored, now, true); currentErr != nil {
			return currentErr
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
	if capacity.DecodeGuestLifecycle(wire, &result) != nil || capacity.GuestRetirementSHA(result) != digest || validateGuestInstallationTx(ctx, tx, stored, receipt, result, recorded) != nil {
		return result, ErrCapacityConflict
	}
	canonical, err := json.Marshal(result)
	if err != nil || !bytes.Equal(canonical, wire) {
		return result, ErrCapacityConflict
	}
	return result, nil
}

func storeGuestInstallationTx(ctx context.Context, tx *sql.Tx, stored guestOriginalStored, receipt model.CapacityGuestOriginalProvisioningReceipt, confirmation model.CapacityGuestOriginalInstallationConfirmation, now time.Time, audit ...func() error) (model.CapacityGuestOriginalInstallationConfirmation, error) {
	var zero model.CapacityGuestOriginalInstallationConfirmation
	if validateGuestInstallationTx(ctx, tx, stored, receipt, confirmation, now) != nil {
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
	if len(audit) > 1 {
		return zero, ErrCapacityConflict
	}
	if len(audit) == 1 {
		if err = audit[0](); err != nil {
			return zero, err
		}
	}
	return confirmation, nil
}

// V2 revalidates the exact immutable registration wire/result clock. A digest
// marker or independently supplied clock cannot replace these original bytes.
func validateGuestInstallationTx(ctx context.Context, tx *sql.Tx, stored guestOriginalStored, receipt model.CapacityGuestOriginalProvisioningReceipt, confirmation model.CapacityGuestOriginalInstallationConfirmation, now time.Time) error {
	if confirmation.Schema != capacity.GuestInstallationV2Schema && confirmation.ProductionClock == nil && receipt.Enrollment.Statement.OriginalProvisioningClockSHA256 == "" {
		return capacity.GuestOriginalInstallation(stored.pre, receipt, confirmation, stored.binding.ProvisionerPublicKey, now)
	}
	var wire []byte
	if err := tx.QueryRowContext(ctx, `SELECT registration_wire FROM public.capacity_vm_original_enrollments WHERE preregistration_id=$1 FOR SHARE`, stored.pre.PreregistrationID).Scan(&wire); err != nil {
		return err
	}
	var registration model.CapacityGuestOriginalProvisioningRegistration
	if capacity.DecodeGuestLifecycle(wire, &registration) != nil || capacity.GuestRetirementSHA(registration) != receipt.OriginalProvisioningSHA256 || capacity.GuestRetirementSHA(registration.Result) != receipt.Enrollment.Statement.OriginalNativeResultSHA256 || registration.Result.ProductionClock == nil || capacity.GuestRetirementSHA(registration.EnrollmentStatement) != capacity.GuestRetirementSHA(receipt.Enrollment.Statement) {
		return ErrCapacityConflict
	}
	if err := loadGuestWitnessTx(ctx, tx, &stored); err != nil {
		return err
	}
	if !capacity.GuestProductionClockStoredMatches(registration.Result.ProductionClock, stored.pre, stored.witness, stored.binding.ProfileManifest) {
		return ErrCapacityConflict
	}
	// Current admission transactions separately call guestCurrentTx. This load
	// also supports immutable historical validation at its actual PG record time.
	var raw []byte
	if err := tx.QueryRowContext(ctx, `SELECT spec FROM public.manifests WHERE id=$1 AND kind='capacity_policy'`, stored.pre.PolicyID).Scan(&raw); err != nil {
		return err
	}
	var policy model.CapacityPolicySpec
	if json.Unmarshal(raw, &policy) != nil || capacity.GuestOriginalRegistration(policy, stored.binding, stored.member, stored.witness, registration, receipt.RecordedAt) != nil || capacity.GuestRetirementEnrollment(policy, stored.binding, stored.member, receipt.Enrollment, receipt.RecordedAt) != nil {
		return ErrCapacityConflict
	}
	return capacity.GuestOriginalInstallationV2(stored.pre, receipt, confirmation, stored.binding.ProvisionerPublicKey, *registration.Result.ProductionClock, now)
}

// One same-original current transaction joins the separately hashed registration
// and result objects before a production workflow records installed membership.
func (s CapacityStore) ValidateGuestOriginalInstallationReceipt(ctx context.Context, principal string, pre model.CapacityGuestOriginalProvisioningPreregistration, receipt model.CapacityGuestOriginalProvisioningReceipt, confirmation model.CapacityGuestOriginalInstallationConfirmation) error {
	return s.guestStoredTransaction(ctx, pre.PreregistrationID, func(tx *sql.Tx, stored guestOriginalStored, now time.Time) error {
		if principal != stored.member.ProvisionerClientPrincipal || capacity.GuestRetirementSHA(pre) != capacity.GuestRetirementSHA(stored.pre) {
			return ErrCapacityMutationAuthorization
		}
		if _, _, err := s.guestCurrentTx(ctx, tx, stored, now, true); err != nil {
			return err
		}
		actual, _, err := loadGuestReceiptTx(ctx, tx, pre.PreregistrationID)
		if err != nil {
			return err
		}
		if capacity.GuestRetirementSHA(actual) != capacity.GuestRetirementSHA(receipt) {
			return ErrCapacityConflict
		}
		return validateGuestInstallationTx(ctx, tx, stored, actual, confirmation, now)
	})
}
