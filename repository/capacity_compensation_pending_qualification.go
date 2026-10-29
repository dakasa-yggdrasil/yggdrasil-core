//go:build linux && nativequalification

package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// Only the two fixed canonical compensation failed-create cases hold their
// accepted source create pending; floor recovery and legacy cases do not.
func canonicalCompensationPendingCase(c string) bool {
	return c == "canonical_compensation_unprotected_failed_create" || c == "canonical_compensation_protected_failed_create"
}

// The accepted original settlement stays the parent's only fact: unconfirmed,
// unregistered and bound to the exact refreshed native create proof.
func canonicalCompensationPendingParent(parent capacityMutationRecord, grant model.CapacityMutationGrant, policy model.Manifest, workflowID uuid.UUID, proof model.CapacityMutationProof) bool {
	if parent.Grant.State != "settled" || parent.Grant.GrantID != grant.GrantID || parent.Grant.CompensationOf != "" || parent.PolicyID != policy.ID || parent.PolicyChecksum != policy.Checksum || parent.WorkflowID != workflowID || parent.Proof != nil {
		return false
	}
	settlement := parent.Settlement
	if settlement == nil || settlement.Outcome != "accepted" || !settlement.TransportCompleted || settlement.ResourceID == "" || settlement.ResourceID != proof.ResourceID || settlement.ResourceCreatedAt != proof.ResourceCreatedAt || len(proof.ActionIDs) != 1 || settlement.ActionID != proof.ActionIDs[0] {
		return false
	}
	if proof.GrantID != grant.GrantID || proof.Slot != grant.Slot || proof.ObservedCreationGrantID != grant.GrantID {
		return false
	}
	expectedGrant := grant
	expectedGrant.State = parent.Grant.State
	return capacity.GuestRetirementSHA(expectedGrant) == capacity.GuestRetirementSHA(parent.Grant)
}

// VerifyCanonicalCompensationPending checks the accepted source create and its
// refreshed native proof without confirming, registering or authorizing cleanup.
// Source cleanup never treats a confirmed member as a failed creation.
func (s CapacityStore) VerifyCanonicalCompensationPending(ctx context.Context, policy model.Manifest, p model.CapacityPolicySpec, nativeCase string, grant model.CapacityMutationGrant, proof model.CapacityMutationProof) error {
	if !canonicalCompensationPendingCase(nativeCase) || grant.Slot != canonicalSourceExpectedSlot(nativeCase) || grant.GrantID == "" || proof.GrantID != grant.GrantID {
		return ErrCapacityConflict
	}
	var preID string
	if err := s.DB.QueryRowContext(ctx, `SELECT id::text FROM public.capacity_vm_provisioning_preregistrations WHERE create_grant_id=$1`, grant.GrantID).Scan(&preID); err != nil {
		return err
	}
	return s.guestStoredTransaction(ctx, preID, func(tx *sql.Tx, stored guestOriginalStored, now time.Time) error {
		return s.verifyCanonicalCompensationPendingTx(ctx, tx, stored, policy, p, nativeCase, grant, proof, now)
	})
}

func (s CapacityStore) verifyCanonicalCompensationPendingTx(ctx context.Context, tx *sql.Tx, stored guestOriginalStored, policy model.Manifest, p model.CapacityPolicySpec, nativeCase string, grant model.CapacityMutationGrant, proof model.CapacityMutationProof, now time.Time) error {
	if !canonicalCompensationPendingCase(nativeCase) || s.ExecutorID != stored.pre.ExecutorID {
		return ErrCapacityConflict
	}
	if _, _, err := s.guestCurrentTx(ctx, tx, stored, now, true); err != nil {
		return err
	}
	var raw []byte
	var parent capacityMutationRecord
	if stored.pre.OriginalCreateGrantID != grant.GrantID || stored.pre.PolicyID != policy.ID.String() || stored.pre.PolicyChecksum != policy.Checksum || stored.pre.Slot != grant.Slot || tx.QueryRowContext(ctx, `SELECT grant_record FROM public.capacity_mutation_grants WHERE id=$1 FOR SHARE`, grant.GrantID).Scan(&raw) != nil || json.Unmarshal(raw, &parent) != nil || !canonicalCompensationPendingParent(parent, grant, policy, s.WorkflowID, proof) {
		return ErrCapacityConflict
	}
	var events, members, failedSlotMembers int
	// Match the stricter source cleanup census across the whole namespace.
	if tx.QueryRowContext(ctx, `SELECT count(*) FROM public.event_log WHERE idempotency_key=$1`, "capacity-mutation/"+grant.GrantID).Scan(&events) != nil || tx.QueryRowContext(ctx, `SELECT count(*) FILTER (WHERE resource_id<>''),count(*) FILTER (WHERE slot=$2 AND resource_id<>'') FROM public.capacity_resource_slots WHERE namespace=$1`, policy.Metadata.Namespace, grant.Slot).Scan(&members, &failedSlotMembers) != nil || events != 0 || members != 1 || failedSlotMembers != 0 {
		return ErrCapacityConflict
	}
	return nil
}
