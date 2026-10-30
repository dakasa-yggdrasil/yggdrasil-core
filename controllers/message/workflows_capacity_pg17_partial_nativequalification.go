//go:build linux && nativequalification

package message

import (
	"context"
	"encoding/json"
	"path/filepath"
	"reflect"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	q "github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacitynativeqemu"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

// Assert only the legitimate reachable geometry. The historical unit's
// unexpired permission under a forcibly expired lease is not reproduced or
// claimed: real issued permissions expire60s before the real300s lease.
func assertPG17OriginalPartial(ctx context.Context, store repository.CapacityStore, policy model.Manifest, binding model.CapacityMutationBinding, fact q.SourceLivePartialContract) (PG17AssertionResult, error) {
	var out PG17AssertionResult
	if originalGuestNativeRealm == nil || ctx.Err() != nil || fact.Schema != "core_original_live_partial_recovery_v1" || fact.Scope != "SOURCE_NATIVE_NEW_MEMBER_PARTIAL_ONLY" || fact.Case != "source_live_partial_recovery" || fact.CoreSource != capacity.CurrentGuestCoreSource() || fact.GuestSource != originalGuestNativeRealm.Request.SourceCommit || fact.PolicyID != policy.ID.String() || fact.WorkflowID != store.WorkflowID.String() || fact.NativeQualified || fact.BaselineUnits != 1 || fact.TargetUnits != 3 || fact.PartialUnits != 2 || fact.MemberRows != 2 || fact.Slot2Grants != 1 || fact.OutstandingMutations != 0 || !fact.PendingPromotionRefused || fact.PendingCreateCalled || fact.PendingGrantID == fact.CreatedGrantID || fact.NextGeneration <= fact.PriorGeneration || fact.RecoveryFence < 2 || !fact.CheckedAt.Before(fact.OriginalDeadline) || !time.Now().UTC().Before(fact.OriginalDeadline) || !reflect.DeepEqual(fact.Refused, []string{"pending_permission_promotion", "incomplete", "wrong_count", "outside_change", "no_mutation", "provider_fence", "new_tuple", "stale_membership"}) {
		return out, errOriginalGuestStep
	}
	var probes []q.QualificationProbeReceipt
	probeRaw, err := q.ReadPrivate(ctx, filepath.Join(originalGuestNativeRealm.PrivateDirectory, "source-live-partial-probes.json"), &probes)
	if err != nil {
		return out, err
	}
	var physical []model.CapacityMutationProof
	physicalRaw, err := q.ReadPrivate(ctx, filepath.Join(originalGuestNativeRealm.PrivateDirectory, "source-live-partial-physical.json"), &physical)
	if err != nil {
		return out, err
	}
	if len(probes) != 2 || len(physical) != 2 || capacity.GuestRetirementSHA(probes) != fact.ProbeSetSHA256 || capacity.GuestRetirementSHA(physical) != fact.PhysicalSetSHA256 || physical[0].Slot != 1 || physical[1].Slot != 2 || physical[0].ResourceID == physical[1].ResourceID || physical[1].ObservedCreationGrantID != fact.CreatedGrantID {
		return out, errOriginalGuestStep
	}
	for _, proof := range physical {
		if !proof.OwnerVerified || !proof.SpecVerified || proof.ResourceID == "" || proof.ObservedCreationGrantID == "" || proof.ObservedAt.Before(fact.StaleMemberDeadline) || !capacity.Fresh(proof.ObservedAt, fact.CheckedAt, 30) {
			return out, errOriginalGuestStep
		}
		var raw []byte
		if err = store.DB.QueryRowContext(ctx, `SELECT grant_record FROM public.capacity_mutation_grants WHERE id=$1 AND namespace=$2`, proof.ObservedCreationGrantID, policy.Metadata.Namespace).Scan(&raw); err != nil {
			return out, err
		}
		var record pg17MutationRecord
		if json.Unmarshal(raw, &record) != nil || record.Grant.State != "confirmed" || record.Grant.Slot != proof.Slot || record.Settlement == nil || record.Settlement.Outcome != "accepted" || !record.Settlement.TransportCompleted || record.Settlement.ResourceID != proof.ResourceID || record.Settlement.ResourceCreatedAt != proof.ResourceCreatedAt || record.PolicyID != fact.PolicyID || record.WorkflowID != fact.WorkflowID {
			return out, errOriginalGuestStep
		}
		var events int
		if err = store.DB.QueryRowContext(ctx, `SELECT count(*) FROM public.event_log WHERE idempotency_key=$1 AND metadata->>'namespace'=$2 AND type='native-qemu.server.ensured'`, "capacity-mutation/"+proof.ObservedCreationGrantID, policy.Metadata.Namespace).Scan(&events); err != nil {
			return out, err
		}
		if events != 1 {
			return out, errOriginalGuestStep
		}
	}
	if err = store.CheckNativeMembershipCoverage(ctx, policy, binding, physical); err != nil {
		return out, err
	}
	var pendingRaw, pendingBefore, preRaw []byte
	if err = store.DB.QueryRowContext(ctx, `SELECT grant_record,jsonb_set(grant_record,'{grant,state}','"issued"'::jsonb) FROM public.capacity_mutation_grants WHERE id=$1 AND namespace=$2`, fact.PendingGrantID, policy.Metadata.Namespace).Scan(&pendingRaw, &pendingBefore); err != nil {
		return out, err
	}
	var pending pg17MutationRecord
	if json.Unmarshal(pendingRaw, &pending) != nil || pending.Grant.State != "expired" || pending.Grant.Slot != 3 || pending.Grant.GrantID != fact.PendingGrantID || pending.PolicyID != fact.PolicyID || pending.WorkflowID != fact.WorkflowID || pending.Generation != fact.PriorGeneration || pending.FencingToken >= fact.RecoveryFence || pending.AttemptID != "" || pending.Settlement != nil || pending.Grant.ExpiresAt.After(fact.LeaseExpiredObservedAt) || capacity.BusinessCreationSHA256(pendingRaw) != fact.PendingAfterSHA256 || capacity.BusinessCreationSHA256(pendingBefore) != fact.PendingBeforeSHA256 {
		return out, errOriginalGuestStep
	}
	if err = store.DB.QueryRowContext(ctx, `SELECT original_wire FROM public.capacity_vm_provisioning_preregistrations WHERE create_grant_id=$1`, fact.PendingGrantID).Scan(&preRaw); err != nil {
		return out, err
	}
	var pre model.CapacityGuestOriginalProvisioningPreregistration
	if capacity.DecodeGuestLifecycle(preRaw, &pre) != nil || pre.Slot != 3 || pre.OriginalCreateGrantID != fact.PendingGrantID || pre.Generation != pending.Generation || pre.Fence != pending.FencingToken || pre.ExecutorID != pending.ExecutorID || pre.LeaseOwner != pending.LeaseOwner || capacity.GuestRetirementSHA(pre) != fact.PendingPreSHA256 {
		return out, errOriginalGuestStep
	}
	var witnesses, native, member3 int
	if err = store.DB.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM public.capacity_guest_original_create_witnesses WHERE preregistration_id=$1),(SELECT count(*) FROM public.capacity_guest_qualification_native_source_returns WHERE preregistration_id=$1),(SELECT count(*) FROM public.capacity_resource_slots WHERE namespace=$2 AND slot=3)`, pre.PreregistrationID, policy.Metadata.Namespace).Scan(&witnesses, &native, &member3); err != nil {
		return out, err
	}
	if witnesses != 0 || native != 0 || member3 != 0 {
		return out, errOriginalGuestStep
	}
	terminalRaw, terminal, err := pg17ReadQualificationIntent(ctx, filepath.Join(originalGuestNativeRealm.PrivateDirectory, "source-live-partial-terminal.json"))
	if err != nil {
		return out, err
	}
	if terminal.Phase != "reconciled_partial" || terminal.Generation != fact.PriorGeneration || terminal.FencingToken != fact.RecoveryFence || terminal.Assessment.Snapshot.Units != 2 || terminal.BaselineSnapshot.Units != 1 || terminal.Decision.Units != 3 || terminal.Decision.ExecutionPermitted || terminal.LeaseOwner != "" || terminal.LeaseExecutorID != "" || capacity.GuestRetirementSHA(terminal) != fact.PartialSHA256 {
		return out, errOriginalGuestStep
	}
	var p model.CapacityPolicySpec
	if json.Unmarshal(policy.Spec, &p) != nil {
		return out, errOriginalGuestStep
	}
	var nextRaw []byte
	if err = store.DB.QueryRowContext(ctx, `SELECT intent FROM public.capacity_intents WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4`, policy.Metadata.Namespace, p.Environment, p.Domain, p.Dimension).Scan(&nextRaw); err != nil {
		return out, err
	}
	var next model.CapacityIntent
	if json.Unmarshal(nextRaw, &next) != nil || next.Generation != fact.NextGeneration || next.RecoveryOnly || next.BaselineSnapshot.Units != 2 || next.Decision.Units != 3 || next.LeaseExecutorID != store.ExecutorID || capacity.GuestRetirementSHA(next) != fact.NextIntentSHA256 {
		return out, errOriginalGuestStep
	}
	return PG17AssertionResult{Schema: "core_pg17_assertion_v1", CaseID: 13, OriginalTest: pg17OriginalNames[13], SourceCase: fact.Case, CoreSource: fact.CoreSource, PolicyID: fact.PolicyID, WorkflowID: fact.WorkflowID, Checks: []string{"baseline_one_actual_second_create_confirmed_members_two_target_three", "actual_pending_permission_never_sent_blocks_negative_promotion", "real_grant_and_lease_expiry_no_clock_edits", "five_recovery_proof_covariates_refused_unchanged", "new_tuple_refused_and_real_stale_membership_refused", "two_same_original_writer_probes_and_fresh_native_members", "ordinary_partial_two_then_new_generation_target_three", "no_unexpired_permission_under_expired_lease_equivalence_claim"}, EvidenceSHA256: []string{capacity.GuestRetirementSHA(fact), capacity.BusinessCreationSHA256(probeRaw), capacity.BusinessCreationSHA256(physicalRaw), fact.PendingBeforeSHA256, fact.PendingAfterSHA256, fact.PendingPreSHA256, capacity.BusinessCreationSHA256(terminalRaw), capacity.BusinessCreationSHA256(nextRaw)}, NativeQualified: false}, nil
}
