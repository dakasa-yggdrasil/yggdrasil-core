package repository

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"reflect"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// Read-only transfer of the remaining ORIGINAL PG deadline. Both selectors are
// signed response content, never a caller duration or permission to adopt a VM.
func (s CapacityStore) GuestOriginalProfileAuthorityV2(ctx context.Context, principal, preID, memberName string, slot int, profileSHA, nativeID, bootID, nonceSHA string, key ed25519.PrivateKey) (model.CapacityGuestOriginalProfileAuthorityV2, error) {
	var out model.CapacityGuestOriginalProfileAuthorityV2
	boot, err := uuid.Parse(bootID)
	if ctx == nil || s.DB == nil || err != nil || boot == uuid.Nil || boot.String() != bootID || !capacity.ValidDigest(nonceSHA) || len(key) != ed25519.PrivateKeySize {
		return out, ErrCapacityMutationAuthorization
	}
	deadline, bounded := ctx.Deadline()
	if !bounded || ctx.Err() != nil || !time.Now().Before(deadline) || time.Until(deadline) > 5*time.Second {
		return out, ErrCapacityConflict
	}
	err = s.guestStoredTransaction(ctx, preID, func(tx *sql.Tx, stored guestOriginalStored, now time.Time) error {
		if principal != stored.member.ProvisionerClientPrincipal || memberName != stored.member.Name || slot != stored.member.Slot || profileSHA != stored.pre.ProfileManifestSHA256 || profileSHA != stored.binding.ProfileManifestSHA256 || stored.binding.EvidenceClass != "owned_provisioner_original" {
			return ErrCapacityMutationAuthorization
		}
		_, _, err := s.guestCurrentTx(ctx, tx, stored, now, true)
		if err != nil {
			return err
		}
		if err = loadGuestWitnessTx(ctx, tx, &stored); err != nil {
			return err
		}
		witness := stored.witness
		if witness.Tuple.ResourceID != nativeID || witness.Tuple.Slot != slot || witness.BindingName != memberName || (witness.Tuple.Provider != "aws" && witness.Tuple.Provider != "hetzner") {
			return ErrCapacityMutationAuthorization
		}
		// Sample after original locks/reads. Revalidate current lease/deadline in
		// PG's own domain; the Guest starts conservatively BEFORE this sample.
		if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
			return err
		}
		policy, _, err := s.guestCurrentTx(ctx, tx, stored, now, true)
		if err != nil {
			return err
		}
		remaining := stored.pre.OriginalDeadline.Sub(now)
		if remaining <= 0 || remaining > capacity.GuestProductionProvisioningLimit || remaining > time.Duration(stored.binding.ProfileManifest.OriginalProvisioningBudgetSeconds)*time.Second {
			return ErrCapacityConflict
		}
		out = model.CapacityGuestOriginalProfileAuthorityV2{Schema: capacity.GuestProfileAuthorityV2Schema, BindingName: memberName, Slot: slot, GuestBootID: bootID, RequestNonceSHA256: nonceSHA, Profile: stored.binding.ProfileManifest, Preregistration: stored.pre, CreateWitness: witness, RemainingNS: int64(remaining), ObservedAt: now.UTC()}
		out.Signature, err = capacity.GuestLifecycleSignature(key, out)
		if err != nil {
			return err
		}
		public := base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
		if !reflect.DeepEqual(out.Preregistration, stored.pre) || capacity.GuestOriginalProfileAuthorityV2(policy, stored.binding, stored.member, out, public, now) != nil {
			return ErrCapacityConflict
		}
		return nil
	})
	if err == nil {
		deadline, ok := ctx.Deadline()
		if !ok || ctx.Err() != nil || !time.Now().Before(deadline) {
			err = ErrCapacityConflict
		}
	}
	if err != nil {
		return model.CapacityGuestOriginalProfileAuthorityV2{}, err
	}
	return out, nil
}
