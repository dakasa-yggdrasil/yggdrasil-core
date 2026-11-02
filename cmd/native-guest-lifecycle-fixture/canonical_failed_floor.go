//go:build linux && nativequalification

package main

import (
	"context"
	"encoding/json"
	message "github.com/dakasa-yggdrasil/yggdrasil-core/controllers/message"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	q "github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacitynativeqemu"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
	"path/filepath"
	"time"
)

func (f *fixture) finishOriginalCanonicalFloorRecovery(ctx context.Context, p model.CapacityPolicySpec, store repository.CapacityStore, bridge q.SourceFloorPolicyBridge, pre model.CapacityGuestOriginalProvisioningPreregistration) error {
	limit := f.request.OriginalStepStartedAt.Add(420 * time.Second)
	if pre.OriginalDeadline.Before(limit) {
		limit = pre.OriginalDeadline
	}
	original, cancel := context.WithDeadline(ctx, limit)
	defer cancel()
	ctx = original
	var raw []byte
	var before model.CapacityIntent
	if err := f.db.QueryRowContext(ctx, `SELECT intent FROM public.capacity_intents WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4`, f.namespace, p.Environment, p.Domain, p.Dimension).Scan(&raw); err != nil {
		return err
	}
	var err error
	var recovered model.CapacityIntent
	var recoveredStore repository.CapacityStore
	if active, recoveryErr := f.realm.OriginalRecoveryCleanupSession(ctx); recoveryErr == nil {
		if json.Unmarshal(raw, &before) != nil || !before.RecoveryOnly || before.PolicyID != f.policy.ID || before.PolicyChecksum != f.policy.Checksum || before.LeaseExecutorID != active.Store.ExecutorID || before.Generation != active.Epoch.Generation || before.FencingToken != active.Epoch.FencingToken {
			return q.ErrOriginalUnknown
		}
		recovered = before
		recoveredStore = active.Store
	} else {
		if json.Unmarshal(raw, &before) != nil || before.PolicyID != f.policy.ID || before.PolicyChecksum != f.policy.Checksum || before.RecoveryOnly || before.Decision.Reason != "protected_floor_recovery" || before.BaselineSnapshot.Units != 1 || before.Decision.Units != 2 || before.LeaseExpiresAt == nil || !before.LeaseExpiresAt.Before(limit) {
			return q.ErrOriginalUnknown
		}
		for {
			var now time.Time
			if err := f.db.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
				return err
			}
			if !now.Before(*before.LeaseExpiresAt) {
				break
			}
			timer := time.NewTimer(20 * time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
		}
		client, err := f.sourceClient(1)
		if err != nil {
			return err
		}
		defer client.Close()
		observed, err := f.realm.DiagnosticProbe(ctx, store, 1, f.corePrivate, client)
		if err != nil {
			return err
		}
		recoveredStore = store
		recoveredStore.ExecutorID = uuid.NewString()
		recovered, err = recoveredStore.Recover(ctx, f.policy, before.Generation, q.QualificationAssessment(p, 1, 0.9, observed.OriginalNativeAfterReturnedAt))
		if err != nil || !recovered.RecoveryOnly || recovered.FencingToken != before.FencingToken+1 || recovered.LeaseOwner == before.LeaseOwner || recovered.LeaseExecutorID != recoveredStore.ExecutorID || recovered.LeaseExpiresAt == nil {
			return q.ErrOriginalUnknown
		}

	}
	client, err := f.sourceClient(1)
	if err != nil {
		return err
	}
	defer client.Close()
	probe, err := f.realm.FloorSourceProbe(ctx, recoveredStore, f.policy, recovered.Generation, recovered.FencingToken, recovered.LeaseOwner, 1, f.corePrivate, client, *recovered.LeaseExpiresAt)
	if err != nil {
		return err
	}
	binding, err := capacity.VMObservationBinding(p, f.binding.MutationBindingName)
	if err != nil {
		return err
	}
	physical, err := f.realm.FreshNativeMember(ctx, 1, binding)
	if err != nil {
		return err
	}
	var desired []byte
	for _, slot := range binding.Slots {
		if slot.Slot == 1 {
			desired, err = json.Marshal(slot.DesiredSpec)
		}
	}
	if err != nil || len(desired) == 0 {
		return q.ErrOriginalUnknown
	}
	if err = recoveredStore.RecordMutationSlot(ctx, f.policy, recovered.Generation, recovered.FencingToken, recovered.LeaseOwner, model.CapacityMutationIssue{BindingName: binding.Name, DesiredSpec: desired}, physical); err != nil {
		return err
	}
	if err = recoveredStore.CheckNativeMembershipCoverage(ctx, f.policy, binding, []model.CapacityMutationProof{physical}); err != nil {
		return err
	}
	var live, foreign int
	if err = f.db.QueryRowContext(ctx, `SELECT count(*),count(*) FILTER(WHERE slot<>1 OR resource_id<>$2) FROM public.capacity_resource_slots WHERE namespace=$1 AND resource_id<>''`, f.namespace, physical.ResourceID).Scan(&live, &foreign); err != nil || live != 1 || foreign != 0 {
		return q.ErrOriginalUnknown
	}
	if _, err = q.Publish(ctx, filepath.Join(f.private, "canonical-floor-baseline-probe.json"), probe); err != nil {
		return err
	}
	if _, err = q.Publish(ctx, filepath.Join(f.private, "canonical-floor-baseline-physical.json"), physical); err != nil {
		return err
	}
	zero := 0
	// This health statement is exclusively the real signed SAME echo writer
	// plus fresh physical baseline1 above, never a production readiness metric.
	proof := model.CapacityTransitionProof{Assessment: q.QualificationAssessment(p, 1, 0.1, probe.OriginalNativeAfterReturnedAt), ObservedAt: probe.OriginalNativeAfterReturnedAt, ReceiptRef: "source-failed-floor-signed-baseline:" + capacity.GuestRetirementSHA(probe), Healthy: true, Inflight: &zero, MutationInflight: &zero, MutationAuthorityKind: "core_mutation_grants", MembershipComplete: true}

	// Re-read actual signed historical cleanup at T300; the effect's old60/150
	// deadline remains historical. Current negative read uses currentRecovery
	// lease and original420/600 only, and can NEVER signal/unlink again.
	currentReadWire, err := recoveredStore.CanonicalSourceFloorCurrentAbsence(ctx, f.policy, pre.OriginalCreateGrantID, recovered.Generation, recovered.FencingToken, recovered.LeaseOwner)
	if err != nil {
		return err
	}
	if _, err = q.PublishBytes(ctx, filepath.Join(f.private, "canonical-floor-failed-slot-current-read.json"), currentReadWire); err != nil {
		return err
	}
	unchanged := func() error {
		var raw []byte
		if err := f.db.QueryRowContext(ctx, `SELECT intent FROM public.capacity_intents WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4`, f.namespace, p.Environment, p.Domain, p.Dimension).Scan(&raw); err != nil {
			return err
		}
		var actual model.CapacityIntent
		if json.Unmarshal(raw, &actual) != nil || capacity.GuestRetirementSHA(actual) != capacity.GuestRetirementSHA(recovered) {
			return q.ErrOriginalUnknown
		}
		return nil
	}
	pg17Floor, pg17FloorErr := message.PG17AssertFailedFloorTerminalNegatives(ctx, f.realm, recoveredStore, f.policy, recovered, proof)
	if pg17FloorErr != nil {
		return pg17FloorErr
	}
	if err = message.PG17RetainAssertions(ctx, f.realm, f.policy, f.workflow.ID.String(), 0, "failed-floor", pg17Floor); err != nil {
		return err
	}
	refused := []string{}
	for _, variant := range []string{"baseline_lost", "membership_incomplete", "wrong_profile", "no_mutation"} {
		bad := proof
		switch variant {
		case "baseline_lost":
			bad.Assessment.Snapshot.Units = 0
		case "membership_incomplete":
			bad.MembershipComplete = false
		case "wrong_profile":
			bad.Assessment.Snapshot.Profile = "foreign-profile"
		case "no_mutation":
			bad.NoMutationVerified = true
		}
		if _, err = recoveredStore.Reconcile(ctx, f.policy, recovered.Generation, recovered.FencingToken, recovered.LeaseOwner, "reconciled_failed_floor", bad); err == nil {
			return q.ErrOriginalUnknown
		}
		if err = unchanged(); err != nil {
			return err
		}
		refused = append(refused, variant)
	}
	if _, err = recoveredStore.Reconcile(ctx, f.policy, recovered.Generation, recovered.FencingToken, recovered.LeaseOwner, "reconciled_partial", proof); err == nil {
		return q.ErrOriginalUnknown
	}
	if err = unchanged(); err != nil {
		return err
	}
	refused = append(refused, "ordinary_partial")
	bad := proof
	bad.NoMutationVerified = true
	if _, err = recoveredStore.Reconcile(ctx, f.policy, recovered.Generation, recovered.FencingToken, recovered.LeaseOwner, "aborted", bad); err == nil {
		return q.ErrOriginalUnknown
	}
	if err = unchanged(); err != nil {
		return err
	}
	refused = append(refused, "aborted_no_mutation")
	terminal, err := recoveredStore.Reconcile(ctx, f.policy, recovered.Generation, recovered.FencingToken, recovered.LeaseOwner, "reconciled_failed_floor", proof)
	if err != nil || terminal.Phase != "reconciled_failed_floor" || !terminal.FloorDegraded || terminal.Assessment.Snapshot.Units != 1 || terminal.Decision.Units != 2 || terminal.Decision.ExecutionPermitted || terminal.LeaseOwner != "" || terminal.LeaseExecutorID != "" || terminal.LeaseExpiresAt != nil {
		return q.ErrOriginalUnknown
	}
	terminalWire, err := recoveredStore.RecordCanonicalFloorTerminal(ctx, f.policy, pre.OriginalCreateGrantID)
	if err != nil || capacity.BusinessCreationSHA256(terminalWire) != capacity.GuestRetirementSHA(terminal) {
		return q.ErrOriginalUnknown
	}
	if _, err = q.PublishBytes(ctx, filepath.Join(f.private, "canonical-floor-terminal-intent.json"), terminalWire); err != nil {
		return err
	}
	// The original real next-generation assessment and claim retain their own
	// current probe/lease. A new create PERMISSION is asserted, not redeemed.
	fresh, err := f.realm.DiagnosticProbe(ctx, recoveredStore, 1, f.corePrivate, client)
	if err != nil {
		return err
	}
	assessment := q.QualificationAssessment(p, 1, 0.9, fresh.OriginalNativeAfterReturnedAt)
	nextRun, _, err := f.originalWorkflow(ctx, failedFloorNextMode, 2, assessment, "")
	if err != nil || nextRun.Status != "succeeded" {
		return q.ErrOriginalUnknown
	}
	var nextRaw []byte
	var next model.CapacityIntent
	if err = f.db.QueryRowContext(ctx, `SELECT intent FROM public.capacity_intents WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4`, f.namespace, p.Environment, p.Domain, p.Dimension).Scan(&nextRaw); err != nil || json.Unmarshal(nextRaw, &next) != nil || next.Generation != terminal.Generation+1 || next.RecoveryOnly || next.Phase != "preparing" || next.Decision.Reason != "protected_floor_recovery" || next.Decision.Units != 2 || next.BaselineSnapshot.Units != 1 {
		return q.ErrOriginalUnknown
	}
	var nextGrant model.CapacityMutationGrant
	grantWire, err := q.ReadPrivate(ctx, filepath.Join(f.private, "canonical-floor-next-grant.json"), &nextGrant)
	if err != nil || nextGrant.State != "issued" || nextGrant.CompensationOf != "" || nextGrant.GrantID == pre.OriginalCreateGrantID {
		return q.ErrOriginalUnknown
	}
	var grantRaw []byte
	var nextPreCount int
	if err = f.db.QueryRowContext(ctx, `SELECT grant_record FROM public.capacity_mutation_grants WHERE id=$1 AND state='issued'`, nextGrant.GrantID).Scan(&grantRaw); err != nil {
		return err
	}
	var stored struct {
		Grant     model.CapacityMutationGrant `json:"grant"`
		AttemptID string                      `json:"attempt_id"`
	}
	if json.Unmarshal(grantRaw, &stored) != nil || stored.Grant != nextGrant || stored.AttemptID != "" {
		return q.ErrOriginalUnknown
	}
	if err = f.db.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_vm_provisioning_preregistrations WHERE create_grant_id=$1 AND (preregistration_record->>'generation')::bigint=$2`, nextGrant.GrantID, next.Generation).Scan(&nextPreCount); err != nil || nextPreCount != 1 {
		return q.ErrOriginalUnknown
	}
	nextWire, err := q.Publish(ctx, filepath.Join(f.private, "canonical-floor-next-intent.json"), next)
	if err != nil {
		return err
	}
	var parentState, childState, childID string
	if err = f.db.QueryRowContext(ctx, `SELECT state FROM public.capacity_mutation_grants WHERE id=$1`, pre.OriginalCreateGrantID).Scan(&parentState); err != nil || parentState != "compensated" {
		return q.ErrOriginalUnknown
	}
	if err = f.db.QueryRowContext(ctx, `SELECT id::text,state FROM public.capacity_mutation_grants WHERE grant_record->'grant'->>'compensation_of'=$1 AND state='confirmed'`, pre.OriginalCreateGrantID).Scan(&childID, &childState); err != nil || childState != "confirmed" {
		return q.ErrOriginalUnknown
	}
	var compensation map[string]json.RawMessage
	compWire, err := q.ReadPrivate(ctx, filepath.Join(f.private, "canonical-source-compensation-result.json"), &compensation)
	if err != nil {
		return err
	}
	bridgeWire, err := json.Marshal(bridge)
	if err != nil {
		return err
	}
	result := map[string]any{"schema": "canonical_source_failed_floor_v1", "scope": "SOURCE_ONLY_ORDINARY_RECONCILE_AFTER_GENERIC_COMPENSATION", "case": f.request.NativeCase, "core_source": capacity.CurrentGuestCoreSource(), "guest_source": f.request.SourceCommit, "parent_grant_id": pre.OriginalCreateGrantID, "child_grant_id": childID, "compensation_result_sha256": capacity.BusinessCreationSHA256(compWire), "policy_bridge_sha256": capacity.BusinessCreationSHA256(bridgeWire), "baseline_probe_sha256": capacity.GuestRetirementSHA(probe), "baseline_physical_sha256": capacity.GuestRetirementSHA(physical), "failed_slot_current_read_sha256": capacity.BusinessCreationSHA256(currentReadWire), "terminal_intent_sha256": capacity.BusinessCreationSHA256(terminalWire), "next_intent_sha256": capacity.BusinessCreationSHA256(nextWire), "next_grant_sha256": capacity.BusinessCreationSHA256(grantWire), "parent_state": parentState, "child_state": childState, "phase": terminal.Phase, "baseline_units": 1, "floor_units": 2, "next_generation": next.Generation, "refused": refused, "next_grant_state": nextGrant.State, "next_grant_redeemed": false, "native_qualified": false, "production_qualified": false}
	if _, err = q.Publish(ctx, filepath.Join(f.private, "canonical-source-failed-floor-result.json"), result); err != nil {
		return err
	}
	pg17Complete, pg17CompleteErr := message.PG17AssertFailedFloorAfterCompletion(ctx, f.realm, store, f.policy, pre.OriginalCreateGrantID)
	if pg17CompleteErr != nil {
		return pg17CompleteErr
	}
	if err = message.PG17RetainAssertions(ctx, f.realm, f.policy, f.workflow.ID.String(), 0, "failed-floor-completed", pg17Complete); err != nil {
		return err
	}
	return nil
}
