package repository

import (
	"context"
	"database/sql"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

const GuestNotifyMaintenanceOperation = "capacity.refresh_original_guest_notify"

func (s CapacityStore) guestNotifyMaintenanceOwner() string {
	return GuestNotifyMaintenanceOwner(s.ExecutorID)
}

// A domain-separated invocation identifier, not a VM lease or provider grant.
func GuestNotifyMaintenanceOwner(executor string) string {
	if !validCapacityExecutor(executor) {
		return ""
	}
	return "notify-maintenance:" + capacity.BusinessCreationSHA256([]byte(executor))
}

func guestNotifyStableEpoch(current model.CapacityIntent) bool {
	return current.Generation > 0 && current.FencingToken > 0 && !current.RecoveryOnly && current.LeaseOwner == "" && current.LeaseExecutorID == "" && current.LeaseExpiresAt == nil && (current.Phase == "promoted" || current.Phase == "reconciled" || current.Phase == "reconciled_partial")
}

// This separate authority can ONLY create/read the fixed synthetic canary.
// It does not claim/renew a VM lease, change a capacity phase, reserve a provider
// grant or declare that a former mutation is quiescent. Scope and epoch are
// reread under the same physical dimension lock on EVERY ledger mutation.
func (s CapacityStore) guestNotifyMaintenanceTransaction(ctx context.Context, policy model.Manifest, generation, fence int64, owner string, discover bool, fn func(*sql.Tx, model.CapacityPolicySpec, model.CapacityIntent, time.Time) error) error {
	origin := s.guestNotifyOrigin
	if s.DB == nil || s.WorkflowID == uuid.Nil || origin == nil || origin.source != capacity.CurrentGuestCoreSource() || origin.step.Use.Kind != "yggdrasil" || origin.step.Use.Operation != GuestNotifyMaintenanceOperation || origin.step.Retry.MaxAttempts > 1 || origin.step.ForEach != nil || origin.step.TimeoutSeconds < 1 || origin.step.TimeoutSeconds > 86400 || s.guestNotifyMaintenanceOwner() == "" || ctx.Err() != nil {
		return ErrCapacityMutationAuthorization
	}
	p, err := parseCapacityPolicy(policy)
	if err != nil || !s.ExecutionEnabled || !p.ExecutionEnabled || p.GuestNotifyCanaryBinding == nil || capacity.ValidateGuestNotifyCanaryBinding(p) != nil {
		return ErrCapacityMutationAuthorization
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = lockMutationScope(ctx, tx, policy.Metadata.Namespace, p); err != nil {
		return err
	}
	var checksum string
	var active bool
	if err = tx.QueryRowContext(ctx, `SELECT checksum,active FROM public.manifests WHERE id=$1 AND kind='capacity_policy' AND namespace=$2 AND name=$3 FOR SHARE`, policy.ID, policy.Metadata.Namespace, policy.Metadata.Name).Scan(&checksum, &active); err != nil {
		return err
	}
	if !active || checksum != policy.Checksum {
		return ErrCapacityConflict
	}
	if err = tx.QueryRowContext(ctx, `SELECT active FROM public.manifests WHERE id=$1 AND kind='workflow' AND namespace=$2 AND name=$3 AND jsonb_typeof(spec->'authorization')='object' FOR SHARE`, s.WorkflowID, p.Workflow.Namespace, p.Workflow.Name).Scan(&active); err != nil {
		return err
	}
	if !active {
		return ErrCapacityMutationAuthorization
	}
	current, err := loadCapacityIntent(ctx, tx, policy.Metadata.Namespace, p, true)
	if err != nil {
		return err
	}
	if !guestNotifyStableEpoch(current) || current.PolicyID != policy.ID || current.PolicyChecksum != policy.Checksum || !discover && (current.Generation != generation || current.FencingToken != fence || owner != s.guestNotifyMaintenanceOwner()) {
		return ErrCapacityConflict
	}
	var unresolved int
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_mutation_grants WHERE NOT(grant_record ? 'authority_kind') AND namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 AND state IN ('issued','redeemed','settled','compensating')`, policy.Metadata.Namespace, p.Environment, p.Domain, p.Dimension).Scan(&unresolved); err != nil {
		return err
	}
	if unresolved != 0 {
		return ErrCapacityConflict
	}
	var now time.Time
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return err
	}
	if err = fn(tx, p, current, now.UTC()); err != nil {
		return err
	}
	return tx.Commit()
}

func (s CapacityStore) guestNotifyTransaction(ctx context.Context, policy model.Manifest, historical bool, generation, fence int64, owner string, fn func(*sql.Tx, model.CapacityPolicySpec, model.CapacityIntent, time.Time) error) error {
	if s.guestNotifyOrigin != nil && s.guestNotifyOrigin.step.Use.Operation == GuestNotifyMaintenanceOperation {
		return s.guestNotifyMaintenanceTransaction(ctx, policy, generation, fence, owner, false, fn)
	}
	return s.mutationTransaction(ctx, policy, historical, generation, fence, owner, fn)
}

func (s CapacityStore) GuestNotifyMaintenanceEpoch(ctx context.Context, policy model.Manifest, preID string) (generation, fence int64, owner string, err error) {
	err = s.guestNotifyMaintenanceTransaction(ctx, policy, 0, 0, "", true, func(tx *sql.Tx, p model.CapacityPolicySpec, current model.CapacityIntent, _ time.Time) error {
		if _, _, e := s.guestNotifyStoredTx(ctx, tx, policy, p, preID); e != nil {
			return e
		}
		generation, fence, owner = current.Generation, current.FencingToken, s.guestNotifyMaintenanceOwner()
		return nil
	})
	return
}
