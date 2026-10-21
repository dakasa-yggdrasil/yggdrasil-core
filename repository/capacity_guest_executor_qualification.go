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

// GuestOriginalExecutorGuardFact is a read-only negative guard experiment, not
// a persisted executor transfer or a successful callback. Its inputs come from
// one repeatable-read snapshot of the actual original grant and preregistration.
type GuestOriginalExecutorGuardFact struct {
	Schema                   string    `json:"schema"`
	GrantID                  string    `json:"grant_id"`
	PreregistrationID        string    `json:"preregistration_id"`
	GrantSHA256              string    `json:"grant_sha256"`
	PreregistrationSHA256    string    `json:"preregistration_sha256"`
	IntentSHA256             string    `json:"intent_sha256"`
	OriginalGuardAccepted    bool      `json:"original_guard_accepted"`
	ExecutorOnlyCloneRefused bool      `json:"executor_only_clone_refused"`
	ForeignIssueRefused      bool      `json:"foreign_issue_refused"`
	CheckedAt                time.Time `json:"checked_at"`
}

// QualifyOriginalGuestExecutorGuard invokes the SAME checkLease used by
// RedeemMutation, first on the actual valid snapshot and then on a negative
// in-memory copy differing only in lease_executor_id. No SQL authority is
// changed, no expiry is substituted and no copied value can reach a writer.
func (s CapacityStore) QualifyOriginalGuestExecutorGuard(ctx context.Context, policy model.Manifest, grantID string) (GuestOriginalExecutorGuardFact, error) {
	var fact GuestOriginalExecutorGuardFact
	p, err := parseCapacityPolicy(policy)
	if err != nil || s.DB == nil || !validCapacityExecutor(grantID) || ctx.Err() != nil {
		return fact, ErrCapacityConflict
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return fact, err
	}
	defer tx.Rollback()
	var grantRaw, preRaw, intentRaw []byte
	var now time.Time
	var r capacityMutationRecord
	if err = tx.QueryRowContext(ctx, `SELECT grant_record,clock_timestamp() FROM public.capacity_mutation_grants WHERE id=$1 AND namespace=$2`, grantID, policy.Metadata.Namespace).Scan(&grantRaw, &now); err != nil {
		return fact, err
	}
	if json.Unmarshal(grantRaw, &r) != nil || r.Grant.GrantID != grantID || r.Grant.State != "issued" || !r.Grant.ExpiresAt.After(now) || r.AttemptID != "" || r.Settlement != nil || r.PolicyID != policy.ID || r.PolicyChecksum != policy.Checksum || r.WorkflowID != s.WorkflowID || r.ExecutorID != s.ExecutorID {
		return fact, ErrCapacityConflict
	}
	if err = tx.QueryRowContext(ctx, `SELECT original_wire FROM public.capacity_vm_provisioning_preregistrations WHERE create_grant_id=$1`, grantID).Scan(&preRaw); err != nil {
		return fact, err
	}
	var pre model.CapacityGuestOriginalProvisioningPreregistration
	if capacity.DecodeGuestLifecycle(preRaw, &pre) != nil || pre.OriginalCreateGrantID != grantID || pre.OriginalCreateRequestSHA256 != r.Grant.RequestSHA256 || pre.PolicyID != policy.ID.String() || pre.PolicyChecksum != policy.Checksum || pre.WorkflowID != r.WorkflowID.String() || pre.ExecutorID != r.ExecutorID || pre.LeaseOwner != r.LeaseOwner || pre.Generation != r.Generation || pre.Fence != r.FencingToken || pre.Slot != r.Grant.Slot || pre.CoreSourceCommit != capacity.CurrentGuestCoreSource() || !pre.OriginalDeadline.After(now) {
		return fact, ErrCapacityConflict
	}
	if err = tx.QueryRowContext(ctx, `SELECT intent FROM public.capacity_intents WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4`, policy.Metadata.Namespace, p.Environment, p.Domain, p.Dimension).Scan(&intentRaw); err != nil {
		return fact, err
	}
	var actual model.CapacityIntent
	if json.Unmarshal(intentRaw, &actual) != nil || s.checkLease(p, policy, &actual, r.Generation, r.FencingToken, r.LeaseOwner, now) != nil {
		return fact, ErrCapacityConflict
	}
	negative := actual
	negative.LeaseExecutorID = uuid.NewString()
	if negative.LeaseExecutorID == actual.LeaseExecutorID || s.checkLease(p, policy, &negative, r.Generation, r.FencingToken, r.LeaseOwner, now) != ErrCapacityLease {
		return fact, ErrCapacityConflict
	}
	fact = GuestOriginalExecutorGuardFact{Schema: "original_guest_executor_guard_readonly_v1", GrantID: grantID, PreregistrationID: pre.PreregistrationID, GrantSHA256: capacity.BusinessCreationSHA256(grantRaw), PreregistrationSHA256: capacity.BusinessCreationSHA256(preRaw), IntentSHA256: capacity.BusinessCreationSHA256(intentRaw), OriginalGuardAccepted: true, ExecutorOnlyCloneRefused: true, CheckedAt: now}
	return fact, tx.Commit()
}
