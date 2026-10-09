package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// ValidateNativeObservationLease uses the existing executor/owner/epoch guard,
// including for an empty inventory or an already-confirmed readback. No new
// lease, provider permission or native effect is created.
func (s CapacityStore) ValidateNativeObservationLease(ctx context.Context, policy model.Manifest, generation, fence int64, owner string) error {
	return s.mutationTransaction(ctx, policy, true, generation, fence, owner, func(_ *sql.Tx, _ model.CapacityPolicySpec, _ model.CapacityIntent, _ time.Time) error { return nil })
}

// NativeMutationReceipt is a protected workflow read, distinct from the adapter
// callback projection. It fixes policy realm, active workflow and exact binding;
// it exposes no owning executor, lease nonce or settlement-token hash.
func (s CapacityStore) NativeMutationReceipt(ctx context.Context, policy model.Manifest, binding model.CapacityMutationBinding, id string) (model.CapacityMutationReceipt, error) {
	var result model.CapacityMutationReceipt
	p, err := parseCapacityPolicy(policy)
	if err != nil || !validCapacityExecutor(id) {
		return result, ErrCapacityMutationAuthorization
	}
	var raw []byte
	if err = s.DB.QueryRowContext(ctx, `SELECT grant_record FROM public.capacity_mutation_grants WHERE id=$1 AND namespace=$2 AND environment=$3 AND domain=$4 AND dimension=$5`, id, policy.Metadata.Namespace, p.Environment, p.Domain, p.Dimension).Scan(&raw); err != nil {
		return result, err
	}
	var record capacityMutationRecord
	if err = json.Unmarshal(raw, &record); err != nil {
		return result, err
	}
	if record.WorkflowID != s.WorkflowID || !sameCompensationBinding(record.Binding, binding) {
		return result, ErrCapacityMutationAuthorization
	}
	// A read may inspect a previous policy revision only within the same exact
	// binding. Existing mutation stores separately enforce historical authority.
	result.Grant, result.AttemptID = record.Grant, record.AttemptID
	if (record.Grant.State == "compensating" || record.Grant.State == "compensated") && record.Grant.CompensationOf == "" && record.Proof != nil {
		proof := *record.Proof
		proof.ActionIDs = append([]string(nil), proof.ActionIDs...)
		proof.AuxiliaryAbsent = append([]model.CapacityMutationAuxiliaryResource(nil), proof.AuxiliaryAbsent...)
		result.NativeReadback = &proof
	}
	if record.Settlement != nil {
		r := record.Settlement
		result.Outcome, result.TransportCompleted = r.Outcome, r.TransportCompleted
		result.ResourceID, result.ResourceCreatedAt = r.ResourceID, r.ResourceCreatedAt
		result.ActionID, result.NextActionIDs = r.ActionID, append([]string(nil), r.NextActionIDs...)
		result.AuxiliaryResources = append([]model.CapacityMutationAuxiliaryResource(nil), r.AuxiliaryResources...)
		result.AuxiliaryInventoryComplete = r.AuxiliaryInventoryComplete
	}
	return result, nil
}

// CheckNativeMembershipCoverage compares fresh native facts against registered
// non-tombstone tuples. It never removes a missing member, revives a tombstone,
// certifies readiness or changes an intent. Partial per-slot registration can be
// retried; complete coverage is reported only after this independent DB check.
func (s CapacityStore) CheckNativeMembershipCoverage(ctx context.Context, policy model.Manifest, b model.CapacityMutationBinding, proofs []model.CapacityMutationProof) error {
	p, err := parseCapacityPolicy(policy)
	if err != nil {
		return err
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT slot,slot_record FROM public.capacity_resource_slots WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 AND integration_instance_id=$5 AND scope_checksum=$6 AND profile_name=$7 AND resource_id<>''`, policy.Metadata.Namespace, p.Environment, p.Domain, p.Dimension, b.IntegrationInstanceID, b.ScopeChecksum, b.ProfileName)
	if err != nil {
		return err
	}
	defer rows.Close()
	seen := map[int]bool{}
	for rows.Next() {
		var slot int
		var raw []byte
		if err = rows.Scan(&slot, &raw); err != nil {
			return err
		}
		var record capacityResourceSlot
		if err = json.Unmarshal(raw, &record); err != nil {
			return err
		}
		matched := false
		for _, proof := range proofs {
			if proof.Slot == slot && proof.ResourceID == record.ResourceID && proof.ResourceCreatedAt == record.ResourceCreatedAt && proof.RequestSHA256 == record.DesiredSpecSHA256 && !record.Tombstone {
				matched = true
			}
		}
		if !matched || seen[slot] {
			return fmt.Errorf("%w: registered native membership differs from complete observation", ErrCapacityConflict)
		}
		seen[slot] = true
	}
	if err = rows.Err(); err != nil {
		return err
	}
	if len(seen) != len(proofs) {
		return fmt.Errorf("%w: native membership is not completely registered", ErrCapacityConflict)
	}
	return nil
}
