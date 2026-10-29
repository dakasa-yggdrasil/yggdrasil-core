//go:build linux && nativequalification

package repository

import (
	"context"
	"database/sql"
	"encoding/json"

	"github.com/google/uuid"
)

// canonicalSourceRedeemChildBound is the pure binding of an unscoped
// (WorkflowID == uuid.Nil) compensation redeem to the already-authenticated
// child grant. The redeem caller carries no workflow of its own, so the only
// workflow it may validate the recovery cleanup lease against is the child's,
// and only when the child is the exact canonical compensation of this parent,
// linked under the same eligibility, issued by the same workflow and at the
// same generation as the parent, and by the recovery epoch's executor.
func canonicalSourceRedeemChildBound(child, parent capacityMutationRecord, childID, linkedParentID, linkedEligibilitySHA, eligibilitySHA, recoveryExecutorID string) bool {
	return childID != "" && child.Grant.GrantID == childID && parent.Grant.GrantID != "" && child.Grant.GrantID != parent.Grant.GrantID && child.Grant.CompensationOf == parent.Grant.GrantID && linkedParentID == parent.Grant.GrantID && eligibilitySHA != "" && linkedEligibilitySHA == eligibilitySHA && child.WorkflowID != uuid.Nil && child.WorkflowID == parent.WorkflowID && child.Generation == parent.Generation && validCapacityExecutor(child.ExecutorID) && child.ExecutorID == recoveryExecutorID
}

// canonicalSourceRedeemLeaseStoreTx returns the store whose WorkflowID the
// recovery cleanup lease is validated against. A scoped store is returned
// unchanged. An unscoped store redeeming a child is scoped to that child's
// workflow only after the child record, read under the held transaction, and
// its canonical cleanup link bind it to this parent and recovery epoch.
// Every refusal returns the zero store. A child bound in every respect but
// issued by an executor other than the current recovery epoch's (the epoch was
// re-prepared after issuance) is refused with ErrCapacityLease, every other
// binding refusal with ErrCapacityConflict.
func (s CapacityStore) canonicalSourceRedeemLeaseStoreTx(ctx context.Context, tx *sql.Tx, parent capacityMutationRecord, childID, eligibilitySHA, recoveryExecutorID string) (CapacityStore, error) {
	if s.WorkflowID != uuid.Nil || childID == "" {
		return s, nil
	}
	var raw []byte
	if err := tx.QueryRowContext(ctx, `SELECT grant_record FROM public.capacity_mutation_grants WHERE id=$1 FOR UPDATE`, childID).Scan(&raw); err != nil {
		return CapacityStore{}, ErrCapacityConflict
	}
	var child capacityMutationRecord
	if err := json.Unmarshal(raw, &child); err != nil {
		return CapacityStore{}, ErrCapacityConflict
	}
	var linked, sha string
	if err := tx.QueryRowContext(ctx, `SELECT parent_grant_id::text,eligibility_sha256 FROM public.capacity_canonical_source_cleanup_children WHERE child_grant_id=$1`, childID).Scan(&linked, &sha); err != nil {
		return CapacityStore{}, ErrCapacityConflict
	}
	if !canonicalSourceRedeemChildBound(child, parent, childID, linked, sha, eligibilitySHA, child.ExecutorID) {
		return CapacityStore{}, ErrCapacityConflict
	}
	if !canonicalSourceRedeemChildBound(child, parent, childID, linked, sha, eligibilitySHA, recoveryExecutorID) {
		return CapacityStore{}, ErrCapacityLease
	}
	scoped := s
	scoped.WorkflowID = child.WorkflowID
	return scoped, nil
}
