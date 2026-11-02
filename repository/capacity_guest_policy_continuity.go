package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

type guestPolicyContinuityQueryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

// guestPolicyContinuityTx admits an installed Guest member whose original
// preregistration was recorded under capacity_policy (priorID, priorChecksum)
// for the CURRENT active policy (ADR-0094). The exact current revision always
// passes. Otherwise the prior row must be an older version of the SAME
// namespace/name capacity_policy with that exact checksum, and it and every
// still-stored version after it, up to the current one, must carry the same
// Guest production contract (capacity.GuestPolicyContinuous). A newer version,
// another policy name, a changed contract, a missing or inactive current row,
// or an unreadable spec all refuse with ErrCapacityConflict.
//
// Manifest spec and checksum columns are immutable after insert, so callers
// that run this outside their locking transaction still recheck the current
// policy's activeness under their own lock.
func guestPolicyContinuityTx(ctx context.Context, q guestPolicyContinuityQueryer, policy model.Manifest, p model.CapacityPolicySpec, priorID, priorChecksum string) error {
	if priorID == policy.ID.String() && priorChecksum == policy.Checksum {
		return nil
	}
	prior, err := uuid.Parse(priorID)
	if err != nil || prior == uuid.Nil || prior == policy.ID || !capacity.ValidDigest(priorChecksum) || !capacity.ValidDigest(capacity.GuestPolicyContinuitySHA256(p)) {
		return ErrCapacityConflict
	}
	var currentVersion int
	var currentChecksum string
	var currentActive bool
	if err = q.QueryRowContext(ctx, `SELECT version,checksum,active FROM public.manifests WHERE id=$1 AND kind='capacity_policy' AND namespace=$2 AND name=$3`, policy.ID, policy.Metadata.Namespace, policy.Metadata.Name).Scan(&currentVersion, &currentChecksum, &currentActive); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrCapacityConflict
		}
		return err
	}
	if !currentActive || currentChecksum != policy.Checksum {
		return ErrCapacityConflict
	}
	return guestPolicyLineageContinuousTx(ctx, q, policy, p, currentVersion, prior, priorChecksum)
}

// guestPolicyLineageContinuousTx is the activeness-free half of
// guestPolicyContinuityTx: (prior, priorChecksum) must be an older version of
// the same namespace/name capacity_policy as `policy` (stored at
// currentVersion), and every stored version from prior up to (excluding) it
// must carry the same Guest contract as p. It never accepts a newer prior, another
// policy name or a changed contract.
func guestPolicyLineageContinuousTx(ctx context.Context, q guestPolicyContinuityQueryer, policy model.Manifest, p model.CapacityPolicySpec, currentVersion int, prior uuid.UUID, priorChecksum string) error {
	if prior == uuid.Nil || prior == policy.ID || !capacity.ValidDigest(priorChecksum) || !capacity.ValidDigest(capacity.GuestPolicyContinuitySHA256(p)) {
		return ErrCapacityConflict
	}
	var priorVersion int
	if err := q.QueryRowContext(ctx, `SELECT version FROM public.manifests WHERE id=$1 AND kind='capacity_policy' AND namespace=$2 AND name=$3 AND checksum=$4`, prior, policy.Metadata.Namespace, policy.Metadata.Name, priorChecksum).Scan(&priorVersion); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrCapacityConflict
		}
		return err
	}
	if priorVersion >= currentVersion {
		return ErrCapacityConflict
	}
	rows, err := q.QueryContext(ctx, `SELECT id,spec FROM public.manifests WHERE kind='capacity_policy' AND namespace=$1 AND name=$2 AND version>=$3 AND version<$4 ORDER BY version,id`, policy.Metadata.Namespace, policy.Metadata.Name, priorVersion, currentVersion)
	if err != nil {
		return err
	}
	defer rows.Close()
	sawPrior := false
	for rows.Next() {
		var id uuid.UUID
		var raw []byte
		if err = rows.Scan(&id, &raw); err != nil {
			return err
		}
		var spec model.CapacityPolicySpec
		if json.Unmarshal(raw, &spec) != nil || !capacity.GuestPolicyContinuous(spec, p) {
			return ErrCapacityConflict
		}
		sawPrior = sawPrior || id == prior
	}
	if err = rows.Err(); err != nil {
		return err
	}
	if !sawPrior {
		return ErrCapacityConflict
	}
	return nil
}

// guestMemberPreregistrationTx finds the ONE installed enrollment of a native
// slot tuple, recorded under this policy or a continuous prior version of it.
// sql.ErrNoRows keeps its historical meaning (no enrollment in this policy
// lineage); an ambiguous or discontinuous enrollment is a conflict.
func guestMemberPreregistrationTx(ctx context.Context, tx *sql.Tx, policy model.Manifest, p model.CapacityPolicySpec, slot int, resourceID, resourceCreatedAt string) (string, error) {
	rows, err := tx.QueryContext(ctx, `SELECT e.preregistration_id::text,pr.preregistration_record->>'policy_id',pr.preregistration_record->>'policy_checksum' FROM public.capacity_vm_original_enrollments e JOIN public.capacity_vm_provisioning_preregistrations pr ON pr.id=e.preregistration_id JOIN public.manifests m ON m.id::text=pr.preregistration_record->>'policy_id' AND m.checksum=pr.preregistration_record->>'policy_checksum' WHERE m.kind='capacity_policy' AND m.namespace=$1 AND m.name=$2 AND (pr.preregistration_record->>'slot')::integer=$3 AND e.enrollment_record->'statement'->'tuple'->>'resource_id'=$4 AND e.enrollment_record->'statement'->'tuple'->>'resource_created_at'=$5 ORDER BY e.preregistration_id`, policy.Metadata.Namespace, policy.Metadata.Name, slot, resourceID, resourceCreatedAt)
	if err != nil {
		return "", err
	}
	type found struct{ id, policyID, checksum string }
	var all []found
	for rows.Next() {
		var f found
		if err = rows.Scan(&f.id, &f.policyID, &f.checksum); err != nil {
			rows.Close()
			return "", err
		}
		all = append(all, f)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return "", err
	}
	rows.Close()
	if len(all) == 0 {
		return "", sql.ErrNoRows
	}
	if len(all) != 1 {
		return "", ErrCapacityConflict
	}
	if err = guestPolicyContinuityTx(ctx, tx, policy, p, all[0].policyID, all[0].checksum); err != nil {
		return "", err
	}
	return all[0].id, nil
}

// guestIssuePolicyContinuityTx proves that an authority issue recorded under
// capacity_policy (issueID, issueChecksum) belongs to the same Guest contract
// lineage as the member's preregistration policy. The issue policy may since
// have been superseded (it is historical provenance), so activeness is not
// required here; callers that act now still check the current policy under
// their own lock. It returns the issue policy's spec for the compatibility-map
// check.
func guestIssuePolicyContinuityTx(ctx context.Context, q guestPolicyContinuityQueryer, issueID, issueChecksum string, pre model.CapacityGuestOriginalProvisioningPreregistration) (model.CapacityPolicySpec, error) {
	var p model.CapacityPolicySpec
	id, err := uuid.Parse(issueID)
	if err != nil || id == uuid.Nil || id.String() != issueID || !capacity.ValidDigest(issueChecksum) {
		return p, ErrCapacityConflict
	}
	issue := model.Manifest{ID: id, Kind: "capacity_policy", Checksum: issueChecksum}
	var version int
	var raw []byte
	if err = q.QueryRowContext(ctx, `SELECT namespace,name,version,spec FROM public.manifests WHERE id=$1 AND kind='capacity_policy' AND checksum=$2 FOR SHARE`, id, issueChecksum).Scan(&issue.Metadata.Namespace, &issue.Metadata.Name, &version, &raw); err != nil {
		return p, err
	}
	if capacity.DecodeNativeCapacity(json.RawMessage(raw), &p) != nil {
		return p, ErrCapacityConflict
	}
	if issueID == pre.PolicyID && issueChecksum == pre.PolicyChecksum {
		return p, nil
	}
	prior, err := uuid.Parse(pre.PolicyID)
	if err != nil || prior.String() != pre.PolicyID {
		return p, ErrCapacityConflict
	}
	if err = guestPolicyLineageContinuousTx(ctx, q, issue, p, version, prior, pre.PolicyChecksum); err != nil {
		return p, err
	}
	return p, nil
}
