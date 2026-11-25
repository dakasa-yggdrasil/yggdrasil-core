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

// Presence alone is always a permanent deny. Corruption can only cause HOLD,
// never authorize another command for an administratively retired subject.
func guardMigratedNativeOriginTx(ctx context.Context, tx *sql.Tx, uid string) error {
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_native_migrated_origin_retirements WHERE subject_uid=$1`, uid).Scan(&n); err != nil {
		return err
	}
	if n != 0 {
		return ErrCapacityConflict
	}
	return nil
}

func migratedNativeOriginValidated(ctx context.Context, tx *sql.Tx, current model.Manifest, p model.CapacityPolicySpec, uid string) (bool, error) {
	var raw []byte
	var sha, namespace, environment, domain, dimension, originID, checkpointSHA string
	var at time.Time
	err := tx.QueryRowContext(ctx, `SELECT retirement_record,record_sha256,namespace,environment,domain,dimension,origin_policy_id::text,checkpoint_sha256,recorded_at FROM public.capacity_native_migrated_origin_retirements WHERE subject_uid=$1 FOR SHARE`, uid).Scan(&raw, &sha, &namespace, &environment, &domain, &dimension, &originID, &checkpointSHA, &at)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var r model.CapacityMigratedNativeOriginRetirement
	if nativeCanonicalArchiveSHA(raw) != sha || capacity.DecodeNativeCapacity(json.RawMessage(raw), &r) != nil || r.Schema != capacity.MigratedNativeOriginSchema || r.Binding.PodUID != uid || r.Binding.OriginPolicyID != originID || r.Binding.CheckpointSHA256 != checkpointSHA || r.OperatorID != r.Binding.OperatorID || !capacity.NativeProcessNonce(r.WorkflowID) || !validCapacityExecutor(r.ExecutorID) || !r.RecordedAt.Equal(at) || namespace != current.Metadata.Namespace || environment != p.Environment || domain != p.Domain || dimension != p.Dimension {
		return false, ErrCapacityConflict
	}
	var currentSHA string
	var currentActive bool
	var currentSpec []byte
	if tx.QueryRowContext(ctx, `SELECT checksum,active,spec FROM public.manifests WHERE id=$1 AND kind='capacity_policy' AND namespace=$2 AND name=$3 FOR SHARE`, current.ID, current.Metadata.Namespace, current.Metadata.Name).Scan(&currentSHA, &currentActive, &currentSpec) != nil || !currentActive || currentSHA != current.Checksum || nativeCanonicalArchiveSHA(currentSpec) != nativeCanonicalArchiveSHA(current.Spec) {
		return false, ErrCapacityConflict
	}
	id, err := uuid.Parse(r.Binding.PolicyID)
	if err != nil {
		return false, ErrCapacityConflict
	}
	recorded, err := scanManifest(tx.QueryRowContext(ctx, `SELECT id,api_version,kind,namespace,name,version,active,description,labels,spec,checksum,created_at,updated_at FROM public.manifests WHERE id=$1 AND kind='capacity_policy' FOR SHARE`, id))
	if err != nil {
		return false, ErrCapacityConflict
	}
	rp, err := parseCapacityPolicy(recorded)
	if err != nil || !nativeAbortQuarantineSameLogicalScope(current, p, recorded, rp) || current.ID.String() == originID || p.AssessmentBinding.Snapshot.WorkloadUID == r.Binding.WorkloadUID || capacity.ValidateMigratedNativeOriginBinding(recorded, rp, r.Binding) != nil || capacity.ValidateMigratedSourceFence(r.Binding, rp, r.RecordedAt) != nil || capacity.ValidateMigratedNativeTarget(rp, r.Binding, r.Target, r.RecordedAt) != nil {
		return false, ErrCapacityConflict
	}
	wid, parseErr := uuid.Parse(r.WorkflowID)
	if parseErr != nil {
		return false, ErrCapacityConflict
	}
	if err = migratedOriginWorkflow(ctx, tx, wid, r.Binding, true); err != nil {
		return false, err
	}
	origin, op, err := migratedOriginPolicy(ctx, tx, current, p, r.Binding)
	if err != nil {
		return false, err
	}
	cp, commands, err := migratedOriginBodies(ctx, tx, origin, op, r.Binding)
	if err != nil || nativeCanonicalArchiveSHA(cp) != nativeCanonicalArchiveSHA(r.Checkpoint) || len(commands) != len(r.Commands) {
		return false, ErrCapacityConflict
	}
	for i := range commands {
		if nativeCanonicalArchiveSHA(commands[i]) != nativeCanonicalArchiveSHA(r.Commands[i]) {
			return false, ErrCapacityConflict
		}
	}
	return true, nil
}

func (s CapacityStore) MigratedNativeOriginRetired(ctx context.Context, policy model.Manifest, uid string) (bool, error) {
	p, err := parseCapacityPolicy(policy)
	if err != nil || s.DB == nil || !capacity.NativeProcessNonce(uid) {
		return false, ErrCapacityConflict
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	if err = lockMutationScope(ctx, tx, policy.Metadata.Namespace, p); err != nil {
		return false, err
	}
	ok, err := migratedNativeOriginValidated(ctx, tx, policy, p, uid)
	if err != nil {
		return false, err
	}
	return ok, tx.Commit()
}

// Enumerate receipts as well as retained rows. A missing original body cannot
// disappear from the validator merely because it no longer joins the ledger.
func migratedNativeOriginCountTx(ctx context.Context, tx *sql.Tx, policy model.Manifest, p model.CapacityPolicySpec) (int, error) {
	rows, err := tx.QueryContext(ctx, `SELECT r.subject_uid FROM public.capacity_native_migrated_origin_retirements r WHERE (r.namespace=$1 AND r.environment=$2 AND r.domain=$3 AND r.dimension=$4) OR EXISTS(SELECT 1 FROM public.capacity_native_lifetimes l WHERE l.pod_uid=r.subject_uid AND l.namespace=$1 AND l.environment=$2 AND l.domain=$3 AND l.dimension=$4) ORDER BY r.subject_uid LIMIT 513`, policy.Metadata.Namespace, p.Environment, p.Domain, p.Dimension)
	if err != nil {
		return 0, err
	}
	uids := []string{}
	for rows.Next() {
		var uid string
		if rows.Scan(&uid) != nil {
			rows.Close()
			return 0, ErrCapacityConflict
		}
		uids = append(uids, uid)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return 0, err
	}
	if len(uids) > maxNativeRetainedLifetimes {
		return 0, ErrCapacityConflict
	}
	for _, uid := range uids {
		ok, e := migratedNativeOriginValidated(ctx, tx, policy, p, uid)
		if e != nil || !ok {
			return 0, ErrCapacityConflict
		}
	}
	return len(uids), nil
}
