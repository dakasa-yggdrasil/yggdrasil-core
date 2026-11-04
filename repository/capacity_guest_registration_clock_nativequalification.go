//go:build linux && nativequalification

package repository

import (
	"context"
	"database/sql"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"time"
)

type GuestQualificationRegistrationClock struct {
	Schema           string    `json:"schema"`
	ObservedAt       time.Time `json:"observed_at"`
	OriginalDeadline time.Time `json:"original_deadline"`
}

// The timestamp is sampled from the same PG transaction after locking the
// original scope. It cannot create admission, renew a lease, or prove future
// clock behavior. This API exists only in native qualification binaries.
func (s CapacityStore) GuestQualificationRegistrationClock(ctx context.Context, principal, id, nonce string) (GuestQualificationRegistrationClock, error) {
	var out GuestQualificationRegistrationClock
	if s.DB == nil || !capacity.ValidDigest(nonce) {
		return out, ErrCapacityMutationAuthorization
	}
	err := s.guestStoredTransaction(ctx, id, func(tx *sql.Tx, stored guestOriginalStored, now time.Time) error {
		if principal != stored.member.ProvisionerClientPrincipal || nonce != stored.pre.NonceSHA256 || stored.binding.EvidenceClass != "native_qemu_qualification" || stored.binding.ProfileManifest.Profile != "qualification-original-echo-writer-v1" || stored.pre.CoreSourceCommit != capacity.CurrentGuestCoreSource() || stored.pre.Slot != stored.member.Slot {
			return ErrCapacityMutationAuthorization
		}
		if _, _, err := s.guestCurrentTx(ctx, tx, stored, now, true); err != nil {
			return err
		}
		if err := loadGuestWitnessTx(ctx, tx, &stored); err != nil {
			return err
		}
		if stored.witness.Tuple.Provider != "native-qemu" || stored.witness.PreregistrationID != stored.pre.PreregistrationID || stored.witness.Tuple.Slot != stored.pre.Slot || !now.Before(stored.pre.OriginalDeadline) {
			return ErrCapacityConflict
		}
		out = GuestQualificationRegistrationClock{Schema: "native_qualification_registration_clock_v1", ObservedAt: now, OriginalDeadline: stored.pre.OriginalDeadline}
		return nil
	})
	return out, err
}
