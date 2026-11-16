//go:build recoveryfixture && !nativequalification

package repository

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// Continue the existing M108 clone after its genuine terminal transaction.
// No new producer, database, root or capacity-clock wait is introduced.
func witnessedExpansionTerminalCohortReturn(t *testing.T, ctx context.Context, f *witnessedCleanup106Fixture, inventories func(bool) []capacity.GuestContractInventory, a WitnessedUnenrolledExpansionCleanup, terminal model.CapacityIntent, cleanupJob CapacityDispatchJob, put func(string, []byte)) {
	t.Helper()
	ledger := func() []byte {
		var raw []byte
		if err := f.DB.QueryRowContext(ctx, `SELECT jsonb_build_object('grants',(SELECT jsonb_agg(to_jsonb(g) ORDER BY id) FROM public.capacity_mutation_grants g),'events',(SELECT jsonb_agg(to_jsonb(e) ORDER BY sequence) FROM public.capacity_witnessed_unenrolled_expansion_cleanup_events e WHERE cleanup_id=$1),'original_job',(SELECT to_jsonb(j) FROM public.capacity_dispatch_jobs j WHERE id=$2),'original_run',(SELECT to_jsonb(w) FROM public.workflow_runs w WHERE id=$3),'preregistration',(SELECT to_jsonb(p) FROM public.capacity_vm_provisioning_preregistrations p WHERE id=$4))::text`, a.ID, a.JobID, a.RunID, a.PreregistrationID).Scan(&raw); err != nil {
			t.Fatal("terminal-return immutable ledger", err)
		}
		return raw
	}
	immutable := ledger()
	finish := func(job CapacityDispatchJob) {
		returned := time.Now().UTC()
		response := model.RunWorkflowResponse{Workflow: model.ManifestReference{ID: f.Workflow.ID, Kind: "workflow", Namespace: f.Workflow.Metadata.Namespace, Name: f.Workflow.Metadata.Name, Version: f.Workflow.Version}, Status: "succeeded", StartedAt: *job.StartedAt, FinishedAt: returned}
		if err := FinishCapacityDispatch(ctx, f.DB, job, response, returned, nil); err != nil {
			t.Fatal("terminal-return real dispatch success/ACK", err)
		}
	}
	finish(cleanupJob) // Must ACK against its still-active original policy.
	publish := func(p model.CapacityPolicySpec) model.Manifest {
		wire := failedServingWire(t, p)
		m, err := CreateManifestVersion(ctx, f.DB, model.ManifestDocument{APIVersion: "v1", Kind: "capacity_policy", Metadata: model.ManifestMetadataInput{Namespace: f.Policy.Metadata.Namespace, Name: f.Policy.Metadata.Name}, Spec: wire}, capacity.BusinessCreationSHA256(wire))
		if err != nil || !m.Metadata.Active || m.ID == f.Policy.ID || m.Version != f.Policy.Version+1 {
			t.Fatal("terminal-return ordinary later policy", m, err)
		}
		f.Policy, f.Spec = m, p
		return m
	}
	start := func(policy model.Manifest) CapacityDispatchJob {
		e := witnessedCleanup106Next(t, f)
		e.Policy = CapacityDispatchManifestPin{ID: policy.ID, Namespace: policy.Metadata.Namespace, Name: policy.Metadata.Name, Version: policy.Version, Checksum: policy.Checksum}
		tx, err := f.DB.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		j, merged, err := EnqueueCapacityDispatch(ctx, tx, e)
		if err != nil || merged || j.JobID != e.JobID || j.WitnessedUnenrolledExpansionCleanupID != "" {
			t.Fatal("terminal-return ordinary new scheduler dispatch", merged, err, j)
		}
		if err = tx.Commit(); err != nil {
			t.Fatal(err)
		}
		j, err = ClaimCapacityDispatch(ctx, f.DB, e.Realm, e.Environment, uuid.New(), time.Duration(f.Spec.LeaseSeconds)*time.Second)
		if err != nil || j.JobID != e.JobID {
			t.Fatal("terminal-return ordinary dispatch claim", err)
		}
		j, err = StartCapacityDispatch(ctx, f.DB, j)
		if err != nil {
			t.Fatal("terminal-return actual dispatch start", err)
		}
		f.private.store.OriginalRunID, f.private.store.ExecutorID = j.RunID, uuid.NewString()
		return j
	}
	collect := func(policy model.Manifest, p model.CapacityPolicySpec, up bool) ([]capacity.GuestContractInventory, model.CapacityAssessment, model.CapacityMetricRangeObservation) {
		now := time.Now().UTC()
		inv := inventories(false)
		retained, err := capacity.GuestContractView(p, f.private.p)
		if err != nil {
			t.Fatal("terminal-return original S1 contract", err)
		}
		snapshot, _, err := capacity.GuestContractReconcileSnapshot(policy, p, []model.CapacityPolicySpec{p, retained}, inv, now)
		if err != nil || len(inv) != 2 || len(inv[0].Inventory.Members) != 0 || len(inv[1].Inventory.Members) != 1 || snapshot.Units != 1 {
			t.Fatal("terminal-return current empty/retained S1 full reducer", err)
		}
		assessment := model.CapacityAssessment{Snapshot: snapshot}
		for _, signal := range p.Signals {
			value := (signal.UpAbove + signal.DownBelow) / 2
			if up {
				value = signal.UpAbove + 1
			}
			assessment.Evidence = append(assessment.Evidence, model.CapacityEvidence{Name: signal.Name, SourceIdentity: signal.SourceIdentity, Unit: signal.Unit, RequireData: true, Matched: true, DataState: "present", Value: &value, RangeMin: &value, RangeMax: &value, SourceSampledAt: now, WindowStart: now.Add(-time.Duration(p.DownHoldSeconds) * time.Second), WindowEnd: now, Samples: p.MinSamples, CoverageComplete: true, MaxGapSeconds: p.MaxSampleGapSeconds})
		}
		if err := capacity.ValidateAssessment(p, assessment, now); err != nil {
			t.Fatal("terminal-return declared complete demand DTO", err)
		}
		return inv, assessment, failedServingReplacementCoverage(p, now)
	}
	// A normal B changes demand policy, never the immutable Guest contract.
	var pB model.CapacityPolicySpec
	if json.Unmarshal(f.Policy.Spec, &pB) != nil {
		t.Fatal("terminal-return independent normal B policy")
	}
	for i := range pB.Signals {
		pB.Signals[i].UpAbove++
	}
	policyB := publish(pB)
	jobB := start(policyB)
	inv, assessment, reporting := collect(policyB, pB, false)
	planStep := f.private.step(t, "plan-original-guest")
	bindPlan := func(values []capacity.GuestContractInventory) CapacityStore {
		return f.private.store.WithOriginalGuestContractReconcile(f.Workflow, planStep, capacity.CurrentGuestCoreSource(), "", "", values, reporting)
	}
	// Each malformed full set must refuse before any claim or ledger change.
	for _, fault := range []string{"missing_current", "missing_retained", "changed_survivor_birth"} {
		var bad []capacity.GuestContractInventory
		if json.Unmarshal(failedServingWire(t, inv), &bad) != nil {
			t.Fatal("terminal-return independent fault copy")
		}
		switch fault {
		case "missing_current":
			bad = bad[1:]
		case "missing_retained":
			bad = bad[:1]
		case "changed_survivor_birth":
			bad[1].Inventory.Members[0].Server.CreatedAt = "2026-01-01T00:00:00Z"
		}
		if _, _, _, err := bindPlan(bad).TryClaimWitnessedExpansionTerminalReconcile(ctx, policyB, assessment); err == nil {
			t.Fatal("terminal-return bad cohort accepted", fault)
		}
		current, err := loadCapacityIntent(ctx, f.DB, policyB.Metadata.Namespace, pB, false)
		if err != nil || current.Generation != terminal.Generation || current.FencingToken != terminal.FencingToken || current.LeaseOwner != "" || current.WitnessedUnenrolledExpansionCleanupID != a.ID || !bytes.Equal(immutable, ledger()) {
			t.Fatal("terminal-return negative changed original terminal", fault, err, current)
		}
	}
	bound, claimed, selected, err := bindPlan(inv).TryClaimWitnessedExpansionTerminalReconcile(ctx, policyB, assessment)
	if err != nil || !selected || claimed.PolicyID != policyB.ID || claimed.PolicyChecksum != policyB.Checksum || claimed.WitnessedExpansionTerminalReconcile == nil || claimed.WitnessedUnenrolledExpansionCleanupID != "" || claimed.Phase != "preparing" || claimed.BaselineSnapshot.Units != 1 || claimed.Generation != terminal.Generation+1 || claimed.FencingToken != terminal.FencingToken+1 || claimed.LeaseOwner == "" || claimed.LeaseExpiresAt == nil || bound.witnessedExpansionOwner != nil {
		t.Fatal("terminal-return actual normal B full-cohort claim", selected, err, claimed)
	}
	completeStep := f.private.step(t, "refresh-original-membership")
	complete := f.private.store.WithOriginalGuestContractReconcile(f.Workflow, completeStep, capacity.CurrentGuestCoreSource(), "refresh", "", inv, reporting)
	complete, epoch, selected, err := complete.OriginalGuestWitnessedExpansionTerminalReconcileEpoch(ctx, policyB)
	if err != nil || !selected || epoch.LeaseOwner != claimed.LeaseOwner || epoch.FencingToken != claimed.FencingToken {
		t.Fatal("terminal-return exact private completion epoch", selected, err)
	}
	complete = complete.WithOriginalGuestNotifyCanary(completeStep, capacity.CurrentGuestCoreSource())
	if _, err = complete.AdvanceOriginalGuest(ctx, policyB, claimed.Generation, claimed.FencingToken, claimed.LeaseOwner, "prepared", assessment); !errors.Is(err, ErrCapacityConflict) {
		t.Fatal("terminal-return old cleanup floor cannot supply new initial usefulness", err)
	}
	// Preserve the existing minimum publication interval and real causal times.
	gap := time.NewTimer(time.Duration(pB.GuestNotifyCanaryBinding.MinimumPublicationIntervalSeconds)*time.Second + time.Millisecond)
	select {
	case <-ctx.Done():
		gap.Stop()
		t.Fatal(ctx.Err())
	case <-gap.C:
	}
	failedServingReplacementCanary(t, ctx, complete, policyB, f.private.p, claimed, f.private.pre, f.private.receipt)
	for _, phase := range []string{"prepared", "canary", "promoted"} {
		inv, assessment, reporting = collect(policyB, pB, false)
		complete = complete.WithOriginalGuestContractReconcile(f.Workflow, completeStep, capacity.CurrentGuestCoreSource(), "provision", "", inv, reporting)
		claimed, err = complete.AdvanceOriginalGuest(ctx, policyB, claimed.Generation, claimed.FencingToken, claimed.LeaseOwner, phase, assessment)
		if err != nil || claimed.Phase != phase {
			t.Fatal("terminal-return real ordinary membership phase", phase, err)
		}
	}
	if claimed.WitnessedExpansionTerminalReconcile != nil || claimed.WitnessedUnenrolledExpansionCleanupID != "" || claimed.LeaseOwner != "" || claimed.LeaseExecutorID != "" || claimed.LeaseExpiresAt != nil || claimed.Assessment.Snapshot.Units != 1 || claimed.Decision.Clock.LastActionAt.IsZero() || !bytes.Equal(immutable, ledger()) {
		t.Fatal("terminal-return did not clear marker/unlease/preserve exact original ledger", claimed)
	}
	promoted := claimed
	finish(jobB)
	// The later A reaches normal Assess, but still obeys the real B action clock.
	// No immediate UP claim, clock rewrite, reduced timer or new 300s producer.
	var pA model.CapacityPolicySpec
	if json.Unmarshal(f.Policy.Spec, &pA) != nil {
		t.Fatal("terminal-return independent next A policy")
	}
	for i := range pA.Signals {
		pA.Signals[i].UpAbove, pA.Signals[i].DownBelow = -1, -2
	}
	policyA := publish(pA)
	jobA := start(policyA)
	inv, assessment, reporting = collect(policyA, pA, true)
	assessed, err := bindPlan(inv).Assess(ctx, policyA, assessment)
	if err != nil || assessed.PolicyID != policyA.ID || assessed.PolicyChecksum != policyA.Checksum || assessed.WitnessedUnenrolledExpansionCleanupID != "" || assessed.WitnessedExpansionTerminalReconcile != nil || assessed.Phase != "hold" || assessed.Decision.Action != "hold" || (assessed.Decision.Reason != "up_window_pending" && assessed.Decision.Reason != "cooldown") || !assessed.Decision.Clock.LastActionAt.Equal(promoted.Decision.Clock.LastActionAt) || assessed.LeaseExpiresAt != nil || !bytes.Equal(immutable, ledger()) {
		t.Fatal("terminal-return fresh A sticky cleanup or skipped genuine clock", err, assessed)
	}
	finish(jobA)
	put("M108-TERMINAL-RETURN-COHORT-B-NEXT-A.PUBLIC.json", failedServingWire(t, map[string]any{"schema": "witnessed_expansion_terminal_cohort_return_postgres_fixture_v1", "fixture_only": true, "normal_B_policy_id": policyB.ID, "normal_B_generation": promoted.Generation, "normal_B_fence": promoted.FencingToken, "normal_B_phase": promoted.Phase, "normal_B_marker_cleared_and_unleased": true, "new_initial_useful_publication_read_required": true, "next_A_policy_id": assessed.PolicyID, "next_A_phase": assessed.Phase, "next_A_reason": assessed.Decision.Reason, "last_action_at_preserved": assessed.Decision.Clock.LastActionAt, "three_incomplete_or_changed_cohort_refusals": true, "whole_cleanup_and_provider_grants_unchanged": true, "capacity_timers_and_real_clocks_unchanged": true, "original_single300_producer_reused": true, "provider_or_Guest_executed": false, "clean_cycle_credit": false}))
}
