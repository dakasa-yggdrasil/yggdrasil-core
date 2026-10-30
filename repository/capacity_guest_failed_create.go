package repository

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"reflect"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// A legacy compensation has no successor epoch operand. After an explicitly
// admitted retirement successor exists it must HOLD, never choose one of the
// two real originals by unspecified query order.
func singleFailedCreateRetirementTx(ctx context.Context, tx *sql.Tx, grantID string) (string, error) {
	var id string
	err := tx.QueryRowContext(ctx, `SELECT min(r.id::text) FROM public.capacity_vm_retirement_intents r JOIN public.capacity_vm_provisioning_preregistrations pre ON pre.id=r.preregistration_id JOIN public.capacity_vm_original_enrollments e ON e.preregistration_id=pre.id WHERE pre.create_grant_id=$1 GROUP BY pre.create_grant_id HAVING count(*)=1`, grantID).Scan(&id)
	return id, err
}

// Never-started is an ORIGINAL source outcome, not the absence of enrollment,
// a 404, an empty cgroup, a failed create action or a signed completeness flag.
// Until its actual prestarter producer and closed return wire are integrated,
// every missing/legacy enrollment stays HOLD. A known enrolled original must
// instead carry the SAME complete original Guest joins and native-off proof.
func (s CapacityStore) guestFailedCreateCleanupTx(ctx context.Context, tx *sql.Tx, p model.CapacityPolicySpec, parent capacityMutationRecord, proof model.CapacityMutationProof, now time.Time, childID string) error {
	if handled, err := s.canonicalSourceFailedCleanupTx(ctx, tx, p, parent, proof, now, childID); handled {
		return err
	}
	if p.GuestRetirementBinding == nil || capacity.ValidateGuestRetirementBinding(p, p.GuestRetirementBinding) != nil {
		return fmt.Errorf("%w: failed create has unknown original writer enrollment; HOLD", ErrCapacityConflict)
	}
	id, err := singleFailedCreateRetirementTx(ctx, tx, parent.Grant.GrantID)
	if err != nil {
		return fmt.Errorf("%w: no original never-started or complete enrolled retirement proof; HOLD", ErrCapacityConflict)
	}
	stored, err := loadGuestRetirementTx(ctx, tx, id)
	if err != nil || !reflect.DeepEqual(stored.Binding, *p.GuestRetirementBinding) || !capacity.GuestOriginalProfileEnabled(p, stored.Binding, stored.Request.Intent.Tuple.Provider) || !capacity.GuestBindingAuthorityCurrent(p, stored.Binding) || stored.Preregistration.OriginalCreateGrantID != parent.Grant.GrantID || stored.Request.Intent.Tuple.InstanceID != parent.Binding.IntegrationInstanceID || stored.Request.Intent.Tuple.ScopeChecksum != parent.Binding.ScopeChecksum || stored.Request.Intent.Slot != parent.Grant.Slot || proof.GrantID != parent.Grant.GrantID || stored.Request.Intent.Tuple.ResourceID != proof.ResourceID || stored.Request.Intent.Tuple.CreatedAt != proof.ResourceCreatedAt {
		return ErrCapacityConflict
	}
	if _, err = guestQuiescentProofTx(ctx, tx, stored); err != nil {
		return err
	}
	var at time.Time
	if err = tx.QueryRowContext(ctx, `SELECT (original_record->'server'->>'observed_at')::timestamptz FROM public.capacity_guest_original_native_poweroff_reads WHERE intent_id=$1 AND original_record->'server'->>'status'='off' ORDER BY recorded_at DESC LIMIT 1`, id).Scan(&at); err != nil || !capacity.Fresh(at, now, stored.Binding.MaxEvidenceAgeSeconds) {
		return ErrCapacityConflict
	}
	if childID != "" {
		var linked string
		var wire []byte
		var digest string
		var raw []byte
		var child capacityMutationRecord
		if tx.QueryRowContext(ctx, `SELECT grant_record FROM public.capacity_mutation_grants WHERE id=$1`, childID).Scan(&raw) != nil || json.Unmarshal(raw, &child) != nil {
			return ErrCapacityConflict
		}
		linked, wire, digest, err = guestCompensationBindingTx(ctx, tx, child)
		if err != nil || linked != id {
			return ErrCapacityConflict
		}
		quiescent, err := guestQuiescentProofTx(ctx, tx, stored)
		if err != nil || digest != capacity.GuestRetirementSHA(quiescent) {
			return ErrCapacityConflict
		}
		var original model.CapacityGuestRetirementObservation
		if capacity.DecodeGuestLifecycle(wire, &original) != nil || !reflect.DeepEqual(original, quiescent) {
			return ErrCapacityConflict
		}
	}
	return nil
}

// guestCompensationBindingTx derives a replacement only from the single
// immutable original binding and a fully closed history of never-redeemed
// siblings. Callers hold the mutation scope lock; issuance/confirmation also
// hold the native-slot lock. No second binding or provider send is invented.
func guestCompensationBindingTx(ctx context.Context, tx *sql.Tx, child capacityMutationRecord) (string, []byte, string, error) {
	var id, digest string
	var wire []byte
	err := tx.QueryRowContext(ctx, `SELECT intent_id::text,original_wire,eligibility_sha256 FROM public.capacity_vm_retirement_delete_bindings WHERE destroy_grant_id=$1`, child.Grant.GrantID).Scan(&id, &wire, &digest)
	if err == nil {
		return id, wire, digest, nil
	}
	if err != sql.ErrNoRows || child.Grant.CompensationOf == "" {
		return "", nil, "", ErrCapacityConflict
	}
	// The original intent is singular for this create. V2 retirement issuance
	// does not use compensation lineage and must never use this derivation.
	id, err = singleFailedCreateRetirementTx(ctx, tx, child.Grant.CompensationOf)
	if err != nil {
		return "", nil, "", ErrCapacityConflict
	}
	var first string
	err = tx.QueryRowContext(ctx, `SELECT b.destroy_grant_id::text,b.original_wire,b.eligibility_sha256 FROM public.capacity_vm_retirement_delete_bindings b JOIN public.capacity_mutation_grants g ON g.id=b.destroy_grant_id WHERE b.intent_id=$1 AND g.grant_record->'grant'->>'compensation_of'=$2`, id, child.Grant.CompensationOf).Scan(&first, &wire, &digest)
	if err != nil {
		return "", nil, "", ErrCapacityConflict
	}
	rows, err := tx.QueryContext(ctx, `SELECT id::text,state,grant_record,expires_at,expires_at=(grant_record->'grant'->>'expires_at')::timestamptz FROM public.capacity_mutation_grants WHERE grant_record->'grant'->>'compensation_of'=$1 AND id<>$2`, child.Grant.CompensationOf, child.Grant.GrantID)
	if err != nil {
		return "", nil, "", err
	}
	defer rows.Close()
	foundFirst, count := false, 0
	for rows.Next() {
		var rowID, state string
		var raw []byte
		var expires time.Time
		var expiryConsistent bool
		var previous capacityMutationRecord
		if rows.Scan(&rowID, &state, &raw, &expires, &expiryConsistent) != nil || json.Unmarshal(raw, &previous) != nil {
			return "", nil, "", ErrCapacityConflict
		}
		count++
		if previous.Grant.GrantID == first {
			foundFirst = true
		}
		if rowID != previous.Grant.GrantID || state != "expired" || previous.Grant.State != "expired" || expires.After(child.CreatedAt) || !expiryConsistent || previous.AttemptID != "" || previous.SettlementTokenSHA256 != "" || previous.Settlement != nil || previous.Proof != nil || previous.Grant.CompensationOf != child.Grant.CompensationOf || previous.Grant.RequestSHA256 != child.Grant.RequestSHA256 || previous.Grant.ExpectedResourceID != child.Grant.ExpectedResourceID || previous.Grant.ExpectedResourceCreatedAt != child.Grant.ExpectedResourceCreatedAt || previous.Grant.Slot != child.Grant.Slot || previous.Grant.BindingName != child.Grant.BindingName || previous.Grant.IntegrationInstanceID != child.Grant.IntegrationInstanceID || previous.Grant.ScopeChecksum != child.Grant.ScopeChecksum || previous.Grant.ProfileName != child.Grant.ProfileName || previous.Grant.Capability != child.Grant.Capability || previous.PolicyID != child.PolicyID || previous.PolicyChecksum != child.PolicyChecksum || previous.WorkflowID != child.WorkflowID || previous.ExecutorID != child.ExecutorID || previous.Generation != child.Generation || !reflect.DeepEqual(previous.Binding, child.Binding) {
			return "", nil, "", ErrCapacityConflict
		}
	}
	if rows.Err() != nil || !foundFirst || count == 0 {
		return "", nil, "", ErrCapacityConflict
	}
	return id, wire, digest, nil
}

// A compensation has an independent current workflow authority but binds to
// the SAME original failed-create retirement, not a fabricated child fence.
func (s CapacityStore) bindGuestCompensationTx(ctx context.Context, tx *sql.Tx, child, parent capacityMutationRecord, now time.Time) error {
	if handled, err := s.canonicalSourceBindCompensationTx(ctx, tx, child, parent, now); handled {
		return err
	}
	id, err := singleFailedCreateRetirementTx(ctx, tx, parent.Grant.GrantID)
	if err != nil {
		return ErrCapacityConflict
	}
	stored, err := loadGuestRetirementTx(ctx, tx, id)
	if err != nil {
		return err
	}
	if stored.Request.Intent.Tuple.ResourceID != child.Grant.ExpectedResourceID || stored.Request.Intent.Tuple.CreatedAt != child.Grant.ExpectedResourceCreatedAt || stored.Request.Intent.Tuple.InstanceID != child.Binding.IntegrationInstanceID || stored.Request.Intent.Tuple.ScopeChecksum != child.Binding.ScopeChecksum || stored.Request.Intent.Slot != child.Grant.Slot || stored.Preregistration.OriginalCreateGrantID != child.Grant.CompensationOf {
		return ErrCapacityConflict
	}
	proof, err := guestQuiescentProofTx(ctx, tx, stored)
	if err != nil {
		return err
	}
	wire, err := json.Marshal(proof)
	if err != nil {
		return err
	}
	var exists bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM public.capacity_vm_retirement_delete_bindings WHERE intent_id=$1)`, id).Scan(&exists); err != nil {
		return err
	}
	if exists {
		linked, originalWire, digest, err := guestCompensationBindingTx(ctx, tx, child)
		if err != nil || linked != id || digest != capacity.GuestRetirementSHA(proof) || !bytes.Equal(originalWire, wire) {
			return ErrCapacityConflict
		}
		return nil
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_vm_retirement_delete_bindings(destroy_grant_id,intent_id,eligibility_sha256,original_eligibility_record,recorded_at,original_wire) VALUES($1,$2,$3,$4::jsonb,$5,$6)`, child.Grant.GrantID, id, capacity.GuestRetirementSHA(proof), string(wire), now, wire)
	return err
}
