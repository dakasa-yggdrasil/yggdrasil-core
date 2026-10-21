//go:build linux && nativequalification

package message

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"path/filepath"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	q "github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacitynativeqemu"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
)

// This hook is AFTER slot2's actual create, settlement, installation, Confirm
// and enrollment return in the original resolved provisioning step. Slot3 is
// only an approved never-sent permission from that same source owner; the
// physical realm cannot Prepare/Create it. No uploaded authority is accepted.
func guestOriginalSourceLivePartial(ctx context.Context, store repository.CapacityStore, policy model.Manifest, p model.CapacityPolicySpec, binding model.CapacityMutationBinding, input guestOriginalStepInput, key ed25519.PrivateKey, step model.WorkflowStepSpec, created model.CapacityMutationGrant, pre model.CapacityGuestOriginalProvisioningPreregistration) (any, bool, error) {
	if originalGuestNativeRealm == nil || !q.SourceLivePartialCase(originalGuestNativeRealm.Request.NativeCase) || input.Slot == 1 {
		return nil, false, nil
	}
	fail := func(err error) (any, bool, error) { return nil, true, errors.Join(errOriginalGuestStep, err) }
	slots := originalGuestNativeRealm.OwnedSlots()
	if input.Slot != 2 || len(slots) != 2 || slots[0] != 1 || slots[1] != 2 || created.Slot != 2 || pre.OriginalCreateGrantID != created.GrantID || binding.MaxSlots != 3 || p.Ceiling != 3 || p.Step != 2 || p.Floor != 1 || p.GuestRetirementBinding == nil || len(p.GuestRetirementBinding.Members) != 3 || ctx.Err() != nil {
		return fail(nil)
	}
	deadline, ok := ctx.Deadline()
	if !ok || deadline.After(pre.OriginalDeadline) {
		return fail(nil)
	}
	readIntent := func() ([]byte, model.CapacityIntent, error) {
		var raw []byte
		var value model.CapacityIntent
		err := store.DB.QueryRowContext(ctx, `SELECT intent FROM public.capacity_intents WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4`, policy.Metadata.Namespace, p.Environment, p.Domain, p.Dimension).Scan(&raw)
		if err == nil {
			err = json.Unmarshal(raw, &value)
		}
		return raw, value, err
	}
	_, before, err := readIntent()
	if err != nil || before.PolicyID != policy.ID || before.Generation != input.Generation || before.FencingToken != input.FencingToken || before.LeaseOwner != input.LeaseOwner || before.LeaseExecutorID != store.ExecutorID || before.LeaseExpiresAt == nil || !before.LeaseExpiresAt.Before(deadline) || before.RecoveryOnly || before.BaselineSnapshot.Units != 1 || before.Decision.Units != 3 || before.BaselineSnapshot.Profile != before.Decision.Profile {
		return fail(err)
	}
	probes, physical, err := sourcePartialMembers(ctx, store, policy, p, binding, input, key, true)
	if err != nil {
		return fail(err)
	}
	if err = store.CheckNativeMembershipCoverage(ctx, policy, binding, physical); err != nil {
		return fail(err)
	}
	var pendingSpec *model.CapacityMutationSpecV1
	for _, candidate := range binding.Slots {
		if candidate.Slot == 3 {
			pendingSpec = candidate.DesiredSpec
		}
	}
	if pendingSpec == nil {
		return fail(nil)
	}
	wire, err := json.Marshal(pendingSpec)
	if err != nil {
		return fail(err)
	}
	nonce, err := sourceGuestNonce()
	if err != nil {
		return fail(err)
	}
	// The same actual resolved step and source context own this logical
	// reservation. There is deliberately no provider Prepare/Create(3).
	pendingStore := store.WithOriginalGuestProvisioning(step, capacity.CurrentGuestCoreSource(), capacity.BusinessCreationSHA256([]byte(nonce)))
	pending, err := pendingStore.IssueMutation(ctx, policy, input.Generation, input.FencingToken, input.LeaseOwner, model.CapacityMutationIssue{BindingName: binding.Name, DesiredSpec: wire})
	if err != nil || pending.State != "issued" || pending.Slot != 3 || pending.GrantID == created.GrantID || !pending.ExpiresAt.After(time.Now().UTC()) {
		return fail(err)
	}
	pendingPre, err := pendingStore.OriginalGuestProvisioning(ctx, pending.GrantID)
	if err != nil || pendingPre.Slot != 3 || pendingPre.ExecutorID != store.ExecutorID || pendingPre.Generation != input.Generation || pendingPre.Fence != input.FencingToken || pendingPre.LeaseOwner != input.LeaseOwner || pendingPre.OriginalDeadline.After(deadline) {
		return fail(err)
	}
	var pendingBefore []byte
	if err = store.DB.QueryRowContext(ctx, `SELECT grant_record FROM public.capacity_mutation_grants WHERE id=$1`, pending.GrantID).Scan(&pendingBefore); err != nil {
		return fail(err)
	}
	proof := sourcePartialProof(p, probes)
	for _, phase := range []string{"prepared", "canary"} {
		if _, err = store.Advance(ctx, policy, input.Generation, input.FencingToken, input.LeaseOwner, phase, proof); err != nil {
			return fail(err)
		}
	}
	canaryRaw, _, err := readIntent()
	if err != nil {
		return fail(err)
	}
	// Units3 is ONLY an explicitly refused promotion covariate. Actual
	// membership and every positive proof remain two original native writers.
	negative := proof
	negative.Assessment.Snapshot.Units = 3
	_, refused := store.Advance(ctx, policy, input.Generation, input.FencingToken, input.LeaseOwner, "promoted", negative)
	if !errors.Is(refused, repository.ErrCapacityConflict) || refused.Error() != repository.ErrCapacityConflict.Error()+": unresolved provider mutation authority" {
		return fail(refused)
	}
	afterNegative, _, err := readIntent()
	if err != nil || !bytes.Equal(canaryRaw, afterNegative) {
		return fail(err)
	}
	// Grant60s and lease300s use their real database clocks. There is no
	// unexpired permission after legitimate recovery; this source case never
	// presents an artificial lease/grant timestamp geometry as equivalent.
	var expiredAt time.Time
	for {
		if err = store.DB.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&expiredAt); err != nil {
			return fail(err)
		}
		if !expiredAt.Before(*before.LeaseExpiresAt) && !expiredAt.Before(pending.ExpiresAt) {
			break
		}
		timer := time.NewTimer(20 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return fail(ctx.Err())
		case <-timer.C:
		}
	}
	diagnostic, err := sourcePartialDiagnostic(ctx, store, p, key)
	if err != nil {
		return fail(err)
	}
	recovery := store
	recovery.ExecutorID = uuid.NewString()
	lease, err := recovery.Recover(ctx, policy, input.Generation, q.QualificationAssessment(p, 2, 0.9, diagnostic.OriginalNativeAfterReturnedAt))
	if err != nil || !lease.RecoveryOnly || lease.FencingToken != input.FencingToken+1 || lease.LeaseOwner == input.LeaseOwner || lease.LeaseExecutorID != recovery.ExecutorID {
		return fail(err)
	}
	current := input
	current.FencingToken, current.LeaseOwner = lease.FencingToken, lease.LeaseOwner
	probes, physical, err = sourcePartialMembers(ctx, recovery, policy, p, binding, current, key, true)
	if err != nil {
		return fail(err)
	}
	proof = sourcePartialProof(p, probes)
	unchanged := func() error {
		_, actual, err := readIntent()
		if err != nil {
			return err
		}
		if capacity.GuestRetirementSHA(actual) != capacity.GuestRetirementSHA(lease) {
			return errOriginalGuestStep
		}
		return nil
	}
	refusals := []string{"pending_permission_promotion"}
	for _, name := range []string{"incomplete", "wrong_count", "outside_change", "no_mutation", "provider_fence"} {
		bad := proof
		switch name {
		case "incomplete":
			bad.MembershipComplete = false
		case "wrong_count":
			bad.Assessment.Snapshot.Units = 1
		case "outside_change":
			bad.Assessment.Snapshot.Units = 4
		case "no_mutation":
			bad.NoMutationVerified = true
		case "provider_fence":
			bad.ProviderFencingToken = lease.FencingToken
		}
		if _, err = recovery.Reconcile(ctx, policy, current.Generation, current.FencingToken, current.LeaseOwner, "reconciled_partial", bad); err == nil {
			return fail(nil)
		}
		if err = unchanged(); err != nil {
			return fail(err)
		}
		refusals = append(refusals, name)
	}
	foreign := physical[1]
	foreign.Slot, foreign.ResourceID = 3, uuid.NewString()
	plan, err := capacity.PrepareMutationPlan(p, model.CapacityMutationIssue{BindingName: binding.Name, DesiredSpec: wire})
	if err != nil {
		return fail(err)
	}
	foreign.RequestSHA256 = plan.RequestSHA256
	if err = recovery.RecordMutationSlot(ctx, policy, current.Generation, current.FencingToken, current.LeaseOwner, model.CapacityMutationIssue{BindingName: binding.Name, DesiredSpec: wire}, foreign); err == nil {
		return fail(nil)
	}
	if err = unchanged(); err != nil {
		return fail(err)
	}
	refusals = append(refusals, "new_tuple")
	staleAt := physical[0].ObservedAt
	for _, observed := range physical {
		if observed.ObservedAt.After(staleAt) {
			staleAt = observed.ObservedAt
		}
	}
	staleAt = staleAt.Add(time.Duration(p.MaxEvidenceAgeSeconds+1) * time.Second)
	if !staleAt.Before(deadline) {
		return fail(nil)
	}
	for {
		var now time.Time
		if err = store.DB.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
			return fail(err)
		}
		if !now.Before(staleAt) {
			break
		}
		timer := time.NewTimer(20 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return fail(ctx.Err())
		case <-timer.C:
		}
	}
	probes, physical, err = sourcePartialMembers(ctx, recovery, policy, p, binding, current, key, false)
	if err != nil {
		return fail(err)
	}
	proof = sourcePartialProof(p, probes)
	_, refused = recovery.Reconcile(ctx, policy, current.Generation, current.FencingToken, current.LeaseOwner, "reconciled_partial", proof)
	if !errors.Is(refused, repository.ErrCapacityConflict) || refused.Error() != repository.ErrCapacityConflict.Error()+": partial recovery inventory does not match fresh immutable native membership" {
		return fail(refused)
	}
	if err = unchanged(); err != nil {
		return fail(err)
	}
	refusals = append(refusals, "stale_membership")
	probes, physical, err = sourcePartialMembers(ctx, recovery, policy, p, binding, current, key, true)
	if err != nil {
		return fail(err)
	}
	if err = recovery.CheckNativeMembershipCoverage(ctx, policy, binding, physical); err != nil {
		return fail(err)
	}
	proof = sourcePartialProof(p, probes)
	terminal, err := recovery.Reconcile(ctx, policy, current.Generation, current.FencingToken, current.LeaseOwner, "reconciled_partial", proof)
	if err != nil || terminal.Phase != "reconciled_partial" || terminal.Assessment.Snapshot.Units != 2 {
		return fail(err)
	}
	var pendingAfter []byte
	if err = store.DB.QueryRowContext(ctx, `SELECT grant_record FROM public.capacity_mutation_grants WHERE id=$1`, pending.GrantID).Scan(&pendingAfter); err != nil {
		return fail(err)
	}
	var pendingRecord pg17MutationRecord
	if json.Unmarshal(pendingAfter, &pendingRecord) != nil || pendingRecord.Grant.State != "expired" || pendingRecord.Grant.GrantID != pending.GrantID || pendingRecord.AttemptID != "" || pendingRecord.Settlement != nil {
		return fail(nil)
	}
	var outstanding, grants2, members, unauthorized int
	if err = store.DB.QueryRowContext(ctx, `SELECT count(*) FILTER(WHERE state IN ('issued','redeemed','settled','compensating')),count(*) FILTER(WHERE slot=2) FROM public.capacity_mutation_grants WHERE namespace=$1`, policy.Metadata.Namespace).Scan(&outstanding, &grants2); err != nil {
		return fail(err)
	}
	if err = store.DB.QueryRowContext(ctx, `SELECT count(*),count(*) FILTER(WHERE slot NOT IN (1,2)) FROM public.capacity_resource_slots WHERE namespace=$1 AND resource_id<>''`, policy.Metadata.Namespace).Scan(&members, &unauthorized); err != nil {
		return fail(err)
	}
	if outstanding != 0 || grants2 != 1 || members != 2 || unauthorized != 0 || len(originalGuestNativeRealm.OwnedSlots()) != 2 {
		return fail(nil)
	}
	assessment := q.QualificationAssessment(p, 2, 0.9, proof.ObservedAt)
	fresh, err := recovery.Assess(ctx, policy, assessment)
	if err != nil || fresh.Generation <= terminal.Generation {
		return fail(err)
	}
	next, err := recovery.Claim(ctx, policy, fresh.Generation, assessment)
	if err != nil || next.Generation != fresh.Generation || next.RecoveryOnly || next.LeaseOwner == "" || next.Decision.Units != 3 {
		return fail(err)
	}
	result := q.SourceLivePartialContract{Schema: "core_original_live_partial_recovery_v1", Scope: "SOURCE_NATIVE_NEW_MEMBER_PARTIAL_ONLY", Case: originalGuestNativeRealm.Request.NativeCase, PolicyID: policy.ID.String(), WorkflowID: store.WorkflowID.String(), CoreSource: capacity.CurrentGuestCoreSource(), GuestSource: originalGuestNativeRealm.Request.SourceCommit, BaselineUnits: 1, TargetUnits: 3, PartialUnits: 2, OutstandingMutations: outstanding, Slot2Grants: grants2, CreatedGrantID: created.GrantID, PendingGrantID: pending.GrantID, PendingBeforeSHA256: capacity.BusinessCreationSHA256(pendingBefore), PendingAfterSHA256: capacity.BusinessCreationSHA256(pendingAfter), PendingPreSHA256: capacity.GuestRetirementSHA(pendingPre), PendingPromotionRefused: true, ProbeSetSHA256: capacity.GuestRetirementSHA(probes), PhysicalSetSHA256: capacity.GuestRetirementSHA(physical), MemberRows: members, ProbeSHA256: capacity.GuestRetirementSHA(probes[0]), PhysicalSHA256: capacity.GuestRetirementSHA(physical[0]), PartialSHA256: capacity.GuestRetirementSHA(terminal), NextGeneration: next.Generation, NextIntentSHA256: capacity.GuestRetirementSHA(next), PriorGeneration: before.Generation, RecoveryFence: lease.FencingToken, Refused: refusals, StaleMemberDeadline: staleAt, LeaseExpiredObservedAt: expiredAt, CheckedAt: time.Now().UTC(), OriginalDeadline: deadline}
	for name, value := range map[string]any{"source-live-partial-probes.json": probes, "source-live-partial-physical.json": physical, "source-live-partial-terminal.json": terminal, "source-live-partial-contract.json": result} {
		if _, err = q.Publish(ctx, filepath.Join(originalGuestNativeRealm.PrivateDirectory, name), value); err != nil {
			return fail(err)
		}
	}
	assertion, err := assertPG17OriginalPartial(ctx, recovery, policy, binding, result)
	if err != nil {
		return fail(err)
	}
	if err = PG17RetainAssertions(ctx, originalGuestNativeRealm, policy, store.WorkflowID.String(), 0, "mutation-partial", []PG17AssertionResult{assertion}); err != nil {
		return fail(err)
	}
	if ctx.Err() != nil || !time.Now().UTC().Before(deadline) {
		return fail(ctx.Err())
	}
	return result, true, nil
}

func sourcePartialProof(p model.CapacityPolicySpec, probes []q.QualificationProbeReceipt) model.CapacityTransitionProof {
	at := probes[0].OriginalNativeAfterReturnedAt
	for _, probe := range probes {
		if probe.OriginalNativeAfterReturnedAt.Before(at) {
			at = probe.OriginalNativeAfterReturnedAt
		}
	}
	zero := 0
	return model.CapacityTransitionProof{Assessment: q.QualificationAssessment(p, len(probes), 0.1, at), ObservedAt: at, ReceiptRef: "original-new-member-partial:" + capacity.GuestRetirementSHA(probes), Healthy: len(probes) == 2, Inflight: &zero, MutationInflight: &zero, MutationAuthorityKind: "core_mutation_grants", MembershipComplete: true}
}

func sourcePartialDiagnostic(ctx context.Context, store repository.CapacityStore, p model.CapacityPolicySpec, key ed25519.PrivateKey) (q.QualificationProbeReceipt, error) {
	var out q.QualificationProbeReceipt
	for _, member := range p.GuestRetirementBinding.Members {
		if member.Slot != 1 {
			continue
		}
		client, err := sourceGuestClient(ctx, store.DB, member)
		if err != nil {
			return out, err
		}
		out, err = originalGuestNativeRealm.DiagnosticProbe(ctx, store, 1, key, client)
		client.Close()
		return out, err
	}
	return out, errOriginalGuestStep
}

func sourcePartialMembers(ctx context.Context, store repository.CapacityStore, policy model.Manifest, p model.CapacityPolicySpec, binding model.CapacityMutationBinding, input guestOriginalStepInput, key ed25519.PrivateKey, record bool) ([]q.QualificationProbeReceipt, []model.CapacityMutationProof, error) {
	if err := store.ValidateNativeObservationLease(ctx, policy, input.Generation, input.FencingToken, input.LeaseOwner); err != nil {
		return nil, nil, err
	}
	current, err := store.Observe(ctx, policy)
	if err != nil || current.LeaseExpiresAt == nil {
		return nil, nil, errOriginalGuestStep
	}
	var probes []q.QualificationProbeReceipt
	var proofs []model.CapacityMutationProof
	for _, slot := range []int{1, 2} {
		var member model.CapacityGuestRetirementMemberBinding
		for _, approved := range p.GuestRetirementBinding.Members {
			if approved.Slot == slot {
				member = approved
			}
		}
		client, err := sourceGuestClient(ctx, store.DB, member)
		if err != nil {
			return nil, nil, err
		}
		var probe q.QualificationProbeReceipt
		if current.RecoveryOnly {
			probe, err = originalGuestNativeRealm.RecoveryProbe(ctx, store, policy, input.Generation, input.FencingToken, input.LeaseOwner, slot, key, client, *current.LeaseExpiresAt)
		} else {
			probe, err = originalGuestNativeRealm.Probe(ctx, store, policy, input.Generation, input.FencingToken, input.LeaseOwner, slot, key, client, *current.LeaseExpiresAt)
		}
		client.Close()
		if err != nil {
			return nil, nil, err
		}
		physical, err := originalGuestNativeRealm.FreshNativeMember(ctx, slot, binding)
		if err != nil {
			return nil, nil, err
		}
		if record {
			var spec *model.CapacityMutationSpecV1
			for _, approved := range binding.Slots {
				if approved.Slot == slot {
					spec = approved.DesiredSpec
				}
			}
			if spec == nil {
				return nil, nil, errOriginalGuestStep
			}
			wire, err := json.Marshal(spec)
			if err != nil {
				return nil, nil, err
			}
			if err = store.RecordMutationSlot(ctx, policy, input.Generation, input.FencingToken, input.LeaseOwner, model.CapacityMutationIssue{BindingName: binding.Name, DesiredSpec: wire}, physical); err != nil {
				return nil, nil, err
			}
		}
		probes = append(probes, probe)
		proofs = append(proofs, physical)
	}
	return probes, proofs, nil
}
