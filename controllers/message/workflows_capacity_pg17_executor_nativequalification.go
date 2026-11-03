//go:build linux && nativequalification

package message

import (
	"context"
	"encoding/json"
	"path/filepath"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	q "github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacitynativeqemu"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

func assertPG17OriginalExecutorFence(ctx context.Context, store repository.CapacityStore, policy model.Manifest, fact q.SourceFenceContract) (PG17AssertionResult, error) {
	var out PG17AssertionResult
	deadline, ok := ctx.Deadline()
	if !ok || deadline.After(fact.OriginalDeadline) || fact.Schema != "core_original_source_fence_contract_v1" || fact.Scope != "SOURCE_CONTRACT_ONLY_NO_NATIVE_AUTHORITY" || fact.Case != "source_contract_executor_fence" || fact.CoreSource != capacity.CurrentGuestCoreSource() || fact.GuestSource != originalGuestNativeRealm.Request.SourceCommit || fact.Namespace != policy.Metadata.Namespace || fact.PolicyID != policy.ID.String() || fact.WorkflowID != store.WorkflowID.String() || fact.Slot != 1 || fact.Generation < 1 || fact.FenceBefore < 1 || fact.FenceAfter != fact.FenceBefore+1 || !fact.RecoveryOnly || !fact.ExecutorChanged || !fact.LeaseOwnerChanged || !fact.OriginalGrantExpired || !fact.OldIssueRefused || fact.RevocationRows != 0 || fact.RevokedID != "" || fact.RevokedKind != "" || fact.NativeQualified || fact.RepositoryRedeemResult != "read_only_after_real_expiry" || fact.GrantTransition != "issued_to_expired_only" || !capacity.ValidDigest(fact.GrantBeforeSHA256) || !capacity.ValidDigest(fact.GrantAfterSHA256) || fact.GrantBeforeSHA256 == fact.GrantAfterSHA256 || fact.CheckedAt.IsZero() || !fact.CheckedAt.Before(fact.OriginalDeadline) || !time.Now().UTC().Before(fact.OriginalDeadline) {
		return out, errOriginalGuestStep
	}
	var guard repository.GuestOriginalExecutorGuardFact
	wire, err := q.ReadPrivate(ctx, filepath.Join(originalGuestNativeRealm.PrivateDirectory, "source-executor-guard-readonly.json"), &guard)
	if err != nil {
		return out, err
	}
	if guard.Schema != "original_guest_executor_guard_readonly_v1" || guard.GrantID != fact.GrantID || guard.PreregistrationID != fact.PreregistrationID || guard.GrantSHA256 != fact.GrantBeforeSHA256 || !capacity.ValidDigest(guard.PreregistrationSHA256) || !capacity.ValidDigest(guard.IntentSHA256) || !guard.OriginalGuardAccepted || !guard.ExecutorOnlyCloneRefused || !guard.ForeignIssueRefused || guard.CheckedAt.IsZero() || !guard.CheckedAt.Before(fact.CheckedAt) {
		return out, errOriginalGuestStep
	}
	var grantRaw, preRaw, intentRaw []byte
	if err = store.DB.QueryRowContext(ctx, `SELECT grant_record FROM public.capacity_mutation_grants WHERE id=$1 AND namespace=$2`, fact.GrantID, policy.Metadata.Namespace).Scan(&grantRaw); err != nil {
		return out, err
	}
	var r pg17MutationRecord
	if json.Unmarshal(grantRaw, &r) != nil || r.Grant.GrantID != fact.GrantID || r.Grant.Slot != 1 || r.Grant.State != "expired" || r.AttemptID != "" || r.Settlement != nil || r.WorkflowID != fact.WorkflowID || r.PolicyID != fact.PolicyID || r.Generation != fact.Generation || r.FencingToken != fact.FenceBefore || r.ExecutorID == "" || r.LeaseOwner == "" || !guard.CheckedAt.Before(r.Grant.ExpiresAt) || r.Grant.ExpiresAt.After(fact.CheckedAt) || capacity.BusinessCreationSHA256(grantRaw) != fact.GrantAfterSHA256 {
		return out, errOriginalGuestStep
	}
	if err = store.DB.QueryRowContext(ctx, `SELECT original_wire FROM public.capacity_vm_provisioning_preregistrations WHERE id=$1 AND create_grant_id=$2`, fact.PreregistrationID, fact.GrantID).Scan(&preRaw); err != nil {
		return out, err
	}
	var pre model.CapacityGuestOriginalProvisioningPreregistration
	if capacity.DecodeGuestLifecycle(preRaw, &pre) != nil || capacity.BusinessCreationSHA256(preRaw) != guard.PreregistrationSHA256 || pre.OriginalCreateGrantID != fact.GrantID || pre.PreregistrationID != fact.PreregistrationID || pre.PolicyID != fact.PolicyID || pre.WorkflowID != fact.WorkflowID || pre.ExecutorID != r.ExecutorID || pre.LeaseOwner != r.LeaseOwner || pre.Generation != fact.Generation || pre.Fence != fact.FenceBefore || fact.OriginalDeadline.After(pre.OriginalDeadline) {
		return out, errOriginalGuestStep
	}
	var p model.CapacityPolicySpec
	if json.Unmarshal(policy.Spec, &p) != nil {
		return out, errOriginalGuestStep
	}
	if err = store.DB.QueryRowContext(ctx, `SELECT intent FROM public.capacity_intents WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4`, policy.Metadata.Namespace, p.Environment, p.Domain, p.Dimension).Scan(&intentRaw); err != nil {
		return out, err
	}
	var intent model.CapacityIntent
	if json.Unmarshal(intentRaw, &intent) != nil || intent.PolicyID != policy.ID || intent.PolicyChecksum != policy.Checksum || intent.Generation != fact.Generation || intent.FencingToken != fact.FenceAfter || !intent.RecoveryOnly || intent.Decision.ExecutionPermitted || intent.LeaseExecutorID == r.ExecutorID || intent.LeaseExecutorID == "" || intent.LeaseOwner == r.LeaseOwner || intent.LeaseOwner == "" {
		return out, errOriginalGuestStep
	}
	var witnesses, returns, members int
	if err = store.DB.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM public.capacity_guest_original_create_witnesses WHERE preregistration_id=$1),(SELECT count(*) FROM public.capacity_guest_qualification_native_source_returns WHERE preregistration_id=$1),(SELECT count(*) FROM public.capacity_resource_slots WHERE namespace=$2)`, fact.PreregistrationID, policy.Metadata.Namespace).Scan(&witnesses, &returns, &members); err != nil {
		return out, err
	}
	h := fact.HTTP
	if witnesses != 0 || returns != 0 || members != 0 || h.Status != 200 || h.Mode != "read_only" || h.ProblemCode != "" || h.BodyBytes <= 0 || h.BodyBytes >= 2<<20 || !capacity.ValidDigest(h.BodySHA256) || h.StartedAt.Before(guard.CheckedAt) || h.DoReturnedAt.Before(h.StartedAt) || h.ReadReturnedAt.Before(h.DoReturnedAt) || h.CloseReturnedAt.Before(h.ReadReturnedAt) || h.CloseReturnedAt.After(fact.CheckedAt) || ctx.Err() != nil {
		return out, errOriginalGuestStep
	}
	return PG17AssertionResult{Schema: "core_pg17_assertion_v1", CaseID: 18, OriginalTest: pg17OriginalNames[18], SourceCase: fact.Case, CoreSource: fact.CoreSource, PolicyID: fact.PolicyID, WorkflowID: fact.WorkflowID, Checks: []string{"unexpired_actual_original_guard_accepts_same_snapshot", "executor_only_negative_clone_same_redeem_guard_exact_lease_refusal", "actual_foreign_invocation_issue_exact_lease_refusal", "no_persisted_executor_transfer_or_redemption_claim", "separate_actual_expiry_recovery_fence_read_only_http", "zero_source_witness_native_returns_members"}, EvidenceSHA256: []string{capacity.BusinessCreationSHA256(wire), guard.GrantSHA256, guard.PreregistrationSHA256, guard.IntentSHA256, capacity.BusinessCreationSHA256(grantRaw), capacity.BusinessCreationSHA256(intentRaw), capacity.GuestRetirementSHA(fact)}, NativeQualified: false}, nil
}
