package message

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/manifest"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	amqp "github.com/rabbitmq/amqp091-go"
)

func guestReconcileOperation(op string) bool {
	return op == capacity.PlanOriginalGuestOperation || op == capacity.CompleteOriginalGuestOperation
}

type originalGuestReconcileOwnerKey struct{}

func captureOriginalGuestReconcileDeadline(ctx context.Context, deadline time.Time) error {
	o, ok := ctx.Value(originalGuestReconcileOwnerKey{}).(*capacity.OriginalGuestReconcileOwner)
	if !ok || o == nil || deadline.IsZero() || !time.Now().Before(deadline) || originalGuestReconcileLive(ctx) != nil {
		return errOriginalGuestStep
	}
	return o.Capture(ctx, deadline)
}

func withOriginalGuestReconcileDeadline(ctx context.Context) (context.Context, context.CancelFunc) {
	o, _ := ctx.Value(originalGuestReconcileOwnerKey{}).(*capacity.OriginalGuestReconcileOwner)
	if o == nil {
		return ctx, func() {}
	}
	return o.Context(ctx)
}

type originalGuestReconcileInput struct {
	Policy       model.ManifestSelector `json:"policy"`
	BindingName  string                 `json:"binding_name,omitempty"`
	Mode         string                 `json:"mode,omitempty"`
	Slot         int                    `json:"slot,omitempty"`
	Generation   int64                  `json:"generation,omitempty"`
	FencingToken int64                  `json:"fencing_token,omitempty"`
	LeaseOwner   string                 `json:"lease_owner,omitempty"`
	RequestID    string                 `json:"request_id,omitempty"`
}

type originalGuestReconcilePlan struct {
	Mode              string `json:"mode"`
	Reason            string `json:"reason"`
	Slot              int    `json:"slot"`
	Generation        int64  `json:"generation"`
	FencingToken      int64  `json:"fencing_token"`
	LeaseOwner        string `json:"lease_owner"`
	PreregistrationID string `json:"preregistration_id"`
}

func originalGuestReconcileLive(ctx context.Context) error {
	deadline, ok := ctx.Deadline()
	if !ok || ctx.Err() != nil || !time.Now().Before(deadline) {
		return errOriginalGuestStep
	}
	return capacityDispatchFence(ctx)
}

// Sources are exact active operator bindings and real adapter responses.
// Neither scheduled inputs nor this collector can set source timestamps,
// values, range coverage, a URL, a profile, native tuple or healthy flag.
func collectOriginalGuestAssessment(ctx context.Context, conn *amqp.Connection, db *sql.DB, policy model.Manifest, p model.CapacityPolicySpec) (model.CapacityVMFleetInventory, model.CapacityAssessment, model.CapacityMetricRangeObservation, error) {
	var inv model.CapacityVMFleetInventory
	var assessment model.CapacityAssessment
	var reporting model.CapacityMetricRangeObservation
	if p.GuestNotifyReconcileBinding == nil || capacity.ValidateGuestNotifyReconcileBinding(p) != nil {
		return inv, assessment, reporting, errOriginalGuestStep
	}
	read := func(binding model.CapacityObservationAdapterBinding, operation string, input map[string]any, out any) error {
		if originalGuestReconcileLive(ctx) != nil {
			return errOriginalGuestStep
		}
		a, err := resolveCapacityObservationAdapter(ctx, conn, db, binding, operation)
		if err != nil {
			return err
		}
		if !capacityBoundCatalogOperation(a.typeSpec, operation) {
			return errOriginalGuestStep
		}
		native, err := capacityDispatchNativePolicy(ctx)
		if err != nil {
			return err
		}
		returned, err := executeIntegrationThroughResolvedWithPolicy(ctx, conn, model.ExecuteIntegrationRequest{Operation: operation, Capability: operation, Input: input}, a.instance, a.instanceSpec, a.typ, a.typeSpec, 65*time.Second, integrationExecutionPolicy{detailFreeErrors: true, safeError: errOriginalGuestStep, requireExplicitResponse: true, nativeHTTP: native})
		if err != nil || originalGuestReconcileLive(ctx) != nil || operation == capacity.VMObserveInventory && returned.Status != "observed" || operation == capacity.ObserveMetricRange && returned.Status != "succeeded" {
			return errOriginalGuestStep
		}
		return capacity.DecodeVMObservation(returned.Output, out)
	}
	return collectOriginalGuestAssessmentFromReads(ctx, policy, p, read)
}

type originalGuestBoundRead func(model.CapacityObservationAdapterBinding, string, map[string]any, any) error

// The live caller above resolves and authenticates each adapter. Keeping the
// ordered reads together also allows qualification of the full decision path.
func collectOriginalGuestAssessmentFromReads(ctx context.Context, policy model.Manifest, p model.CapacityPolicySpec, read originalGuestBoundRead) (model.CapacityVMFleetInventory, model.CapacityAssessment, model.CapacityMetricRangeObservation, error) {
	var inv model.CapacityVMFleetInventory
	var assessment model.CapacityAssessment
	var reporting model.CapacityMetricRangeObservation
	if p.GuestNotifyReconcileBinding == nil || capacity.ValidateGuestNotifyReconcileBinding(p) != nil || read == nil {
		return inv, assessment, reporting, errOriginalGuestStep
	}
	b := p.MutationBindings[0]
	revision := model.CapacityObservationAdapterBinding{IntegrationInstanceID: b.IntegrationInstanceID, InstanceChecksum: b.IntegrationChecksum, IntegrationTypeID: b.IntegrationTypeID, TypeChecksum: b.IntegrationTypeChecksum}
	if err := read(revision, capacity.VMObserveInventory, map[string]any{"profile": b.ProfileName}, &inv); err != nil {
		return inv, assessment, reporting, err
	}
	var err error
	assessment.Snapshot, err = capacity.GuestReconcileSnapshot(policy, p, inv, time.Now().UTC())
	if err != nil || originalGuestReconcileLive(ctx) != nil {
		return inv, assessment, reporting, errOriginalGuestStep
	}
	// A complete, fresh native inventory proves whether the protected floor is
	// absent. Demand telemetry is unavailable before the first Guest reports;
	// the planner already permits only floor repair without that telemetry.
	// Ordinary scale and every member/readiness proof retain strict signals.
	assessment.Evidence, err = collectOriginalGuestDemand(p, assessment.Snapshot, func(binding model.CapacityMetricSignalBinding) (model.CapacityMetricRangeObservation, error) {
		var raw model.CapacityMetricRangeObservation
		err := read(binding.Adapter, capacity.ObserveMetricRange, map[string]any{"binding": binding.BindingName}, &raw)
		return raw, err
	})
	if err != nil {
		return inv, assessment, reporting, err
	}
	coverage := *p.GuestNotifyReconcileBinding.MemberCoverage
	if err = read(coverage.Adapter, capacity.ObserveMetricRange, map[string]any{"binding": coverage.BindingName}, &reporting); err != nil {
		return inv, assessment, reporting, err
	}
	if err = capacity.GuestReconcileMemberCoverage(p, reporting, assessment.Snapshot.Units, time.Now().UTC()); err != nil {
		return inv, assessment, reporting, err
	}
	return inv, assessment, reporting, nil
}

// The caller must supply the snapshot returned by GuestReconcileSnapshot
// from the actual complete provider inventory. No caller-supplied unit count
// crosses the workflow boundary. Missing demand is permitted only below the
// fixed floor; the independent membership-coverage read is still mandatory.
func collectOriginalGuestDemand(p model.CapacityPolicySpec, snapshot model.CapacitySnapshot, read func(model.CapacityMetricSignalBinding) (model.CapacityMetricRangeObservation, error)) ([]model.CapacityEvidence, error) {
	if snapshot.Units < p.Floor {
		return nil, nil
	}
	var evidence []model.CapacityEvidence
	for _, binding := range p.GuestNotifyReconcileBinding.Signals {
		raw, err := read(binding)
		if err != nil {
			return nil, err
		}
		e, err := capacity.BoundMetricEvidence(p, binding, raw, time.Now().UTC())
		if err != nil {
			return nil, err
		}
		evidence = append(evidence, e)
	}
	return evidence, nil
}

func originalGuestNextSlot(p model.CapacityPolicySpec, inv model.CapacityVMFleetInventory, members []repository.GuestNotifyFloorMember, decision model.CapacityDecision) (string, int, string, error) {
	if decision.Profile != p.Profiles[0].Name {
		return "", 0, "", errOriginalGuestStep
	}
	switch decision.Action {
	case "expand", "prepare":
		if decision.Units != len(members)+1 || len(inv.MissingSlots) == 0 {
			return "", 0, "", errOriginalGuestStep
		}
		slot := inv.MissingSlots[0]
		for _, candidate := range inv.MissingSlots {
			if candidate < slot {
				slot = candidate
			}
		}
		return "provision", slot, "", nil
	case "drain":
		if decision.Units != len(members)-1 || decision.Units < p.Floor {
			return "", 0, "", errOriginalGuestStep
		}
		var selected repository.GuestNotifyFloorMember
		for _, member := range members {
			if member.Slot > p.MutationBindings[0].ProtectedSlots && member.Slot > selected.Slot {
				selected = member
			}
		}
		if selected.Slot == 0 {
			return "", 0, "", errOriginalGuestStep
		}
		return "retire", selected.Slot, selected.PreregistrationID, nil
	}
	return "", 0, "", errOriginalGuestStep
}

// Only the plan operation may defer an incomplete reporting-membership proof,
// and only to attempt an already requested failed-installed disposal claim.
// Every other refusal, and every other operation, stays strict.
func originalGuestPlanCoverageMayDefer(operation string, err error) bool {
	return operation == capacity.PlanOriginalGuestOperation && errors.Is(err, capacity.ErrOriginalGuestReportingIncomplete)
}

func executeOriginalGuestReconcileStep(parent context.Context, conn *amqp.Connection, db *sql.DB, wfRef model.ManifestReference, step model.WorkflowStepSpec, result model.WorkflowRunStepResult, input map[string]any) model.WorkflowRunStepResult {
	parent, stopOwner := withOriginalGuestReconcileDeadline(parent)
	defer stopOwner()
	result.Attempts = 1
	stage := "input"
	fail := func(err error) model.WorkflowRunStepResult {
		capacityDispatchCause(parent, err)
		result.Status = "failed"
		result.Error = "original Guest reconciliation held"
		result.Metadata = map[string]any{"original_guest_reconcile_refusal_stage": stage}
		if n := originalGuestNotifyProbeStage(err); n != "" {
			result.Metadata["original_guest_notify_refusal_stage"] = n
		}
		if d, ok := originalGuestNotifyNonceDiagnostic(err); ok {
			result.Metadata["original_guest_notify_nonce_http_status"] = d.Status
			if d.Code != "" {
				result.Metadata["original_guest_notify_nonce_problem_code"] = d.Code
			}
		}
		result.FinishedAt = time.Now().UTC()
		return result
	}
	if db == nil || conn == nil || !guestReconcileOperation(step.Use.Operation) || result.Operation != step.Use.Operation || step.TimeoutSeconds < 1 || step.TimeoutSeconds > 600 {
		return fail(errOriginalGuestStep)
	}
	ctx, cancel := context.WithTimeout(parent, time.Duration(step.TimeoutSeconds)*time.Second)
	defer cancel()
	if originalGuestReconcileLive(ctx) != nil {
		return fail(errOriginalGuestStep)
	}
	var parsed originalGuestReconcileInput
	if capacity.DecodeVMObservation(input, &parsed) != nil || parsed.Policy.ManifestID != "" || parsed.Policy.Version != nil || parsed.Policy.Namespace == "" || parsed.Policy.Name == "" {
		return fail(errOriginalGuestStep)
	}
	policy, err := repository.ResolveManifest(ctx, db, "capacity_policy", parsed.Policy.Namespace, parsed.Policy.Name, nil, true)
	if err != nil {
		return fail(err)
	}
	p, err := manifest.ParseCapacityPolicySpec(policy.Spec)
	if err != nil || manifest.ValidateCapacityPolicySpec(p) != nil || p.GuestNotifyReconcileBinding == nil || wfRef.Namespace != p.Workflow.Namespace || wfRef.Name != p.Workflow.Name || !capacity.GuestOriginalProfileEnabled(p, *p.GuestRetirementBinding, p.Profiles[0].Provider) {
		return fail(errOriginalGuestStep)
	}
	wf, err := repository.ResolveManifest(ctx, db, "workflow", p.Workflow.Namespace, p.Workflow.Name, nil, true)
	var wfs model.WorkflowManifestSpec
	if err != nil || wf.ID != wfRef.ID || wf.Version != wfRef.Version || json.Unmarshal(wf.Spec, &wfs) != nil || capacity.ValidateOriginalGuestReconcileGraph(wfs, policy, p) != nil {
		return fail(errOriginalGuestStep)
	}
	found := false
	for _, candidate := range wfs.Steps {
		found = found || reflect.DeepEqual(candidate, step)
	}
	if !found {
		return fail(errOriginalGuestStep)
	}
	executor, _ := ctx.Value(capacityInvocationKey{}).(string)
	store := repository.CapacityStore{DB: db, ExecutionEnabled: capacityExecutionEnabled(), WorkflowID: wf.ID, ExecutorID: executor, OriginalRunID: capacityDispatchOriginalRun(ctx)}
	if !store.ExecutionEnabled || !p.ExecutionEnabled {
		return fail(repository.ErrCapacityDisabled)
	}
	if step.Use.Operation == capacity.PlanOriginalGuestOperation && (len(input) != 1 || parsed.Mode != "" || parsed.Slot != 0 || parsed.Generation != 0 || parsed.FencingToken != 0 || parsed.LeaseOwner != "" || parsed.RequestID != "") {
		return fail(errOriginalGuestStep)
	}
	if step.Use.Operation == capacity.CompleteOriginalGuestOperation {
		if parsed.Mode != "provision" && parsed.Mode != "retire" && parsed.Mode != "refresh" {
			return fail(errOriginalGuestStep)
		}
		if parsed.Mode == "refresh" && (len(input) != 2 || parsed.Slot != 0 || parsed.Generation != 0 || parsed.FencingToken != 0 || parsed.LeaseOwner != "" || parsed.RequestID != "") || parsed.Mode != "refresh" && (parsed.BindingName != p.MutationBindings[0].Name || parsed.Slot < 1 || parsed.Slot > 8 || parsed.Generation < 1 || parsed.FencingToken < 1 || parsed.LeaseOwner == "") || (parsed.Mode == "retire") != (parsed.RequestID != "") {
			return fail(errOriginalGuestStep)
		}
	}
	if step.Use.Operation == capacity.PlanOriginalGuestOperation || parsed.Mode == "retire" {
		serving, quarantined, servingErr := store.FailedServingGuestDisposalWaiting(ctx, policy)
		if servingErr != nil {
			return fail(servingErr)
		}
		if quarantined {
			result.Metadata = map[string]any{"mode": "hold", "reason": "serving_guest_quarantined", "admission_id": serving.ID, "historical_use_preserved": true, "business_effects_preserved": true, "native_write_sent": false}
			result.Status, result.Error, result.FinishedAt = "succeeded", "", time.Now().UTC()
			return result
		}
		early := store.WithOriginalGuestReconcile(wf, step, capacity.CurrentGuestCoreSource(), parsed.Mode, parsed.RequestID, model.CapacityVMFleetInventory{}, model.CapacityMetricRangeObservation{})
		held, waiting, e := early.FailedInstalledGuestDisposalWaiting(ctx, policy, parsed.RequestID)
		if e != nil {
			return fail(e)
		}
		if waiting {
			output := map[string]any{"mode": "hold", "reason": "failed_installed_explicit_native_cleanup_pending", "admission_id": held.ID, "retirement_request_id": held.RetirementRequestID, "useful_capacity_credit": 0, "native_destroy_sent": false, "original_business_effects_preserved": true}
			raw, e := json.Marshal(output)
			if e != nil || json.Unmarshal(raw, &result.Metadata) != nil || originalGuestReconcileLive(ctx) != nil {
				return fail(errOriginalGuestStep)
			}
			result.Status, result.Error, result.FinishedAt = "succeeded", "", time.Now().UTC()
			return result
		}
	}
	if step.Use.Operation == capacity.PlanOriginalGuestOperation || step.Use.Operation == capacity.CompleteOriginalGuestOperation && parsed.Mode == "retire" {
		var cleanup any
		var handled bool
		var cleanupErr error
		if step.Use.Operation == capacity.PlanOriginalGuestOperation {
			cleanup, handled, cleanupErr = planFailedExpansionCleanup(ctx, store, policy, wf, step)
		} else {
			cleanup, handled, cleanupErr = completeFailedExpansionCleanup(ctx, store, policy, wf, p, step, parsed)
		}
		if cleanupErr != nil {
			return fail(cleanupErr)
		}
		if handled {
			raw, e := json.Marshal(cleanup)
			if e != nil || json.Unmarshal(raw, &result.Metadata) != nil {
				return fail(errOriginalGuestStep)
			}
			result.Status = "succeeded"
			result.Error = ""
			result.FinishedAt = time.Now().UTC()
			return result
		}
	}
	// An authenticated historical forward claim must be selected before the
	// powered-off target is asked to satisfy aggregate useful coverage.
	if step.Use.Operation == capacity.PlanOriginalGuestOperation {
		forward, handled, forwardErr := planGuestRetirementForward(ctx, store, policy, wf, step)
		if forwardErr != nil {
			return fail(forwardErr)
		}
		if handled {
			raw, e := json.Marshal(forward)
			if e != nil || json.Unmarshal(raw, &result.Metadata) != nil || originalGuestReconcileLive(ctx) != nil {
				return fail(errOriginalGuestStep)
			}
			result.Status, result.Error, result.FinishedAt = "succeeded", "", time.Now().UTC()
			return result
		}
	}
	var inv model.CapacityVMFleetInventory
	var assessment model.CapacityAssessment
	var reporting model.CapacityMetricRangeObservation
	collect := func(readCtx context.Context) error {
		var e error
		inv, assessment, reporting, e = collectOriginalGuestAssessment(readCtx, conn, db, policy, p)
		return e
	}
	stage = "source_assessment"
	if step.Use.Operation == capacity.CompleteOriginalGuestOperation && parsed.Mode != "refresh" {
		err = capacity.AwaitOriginalGuestReporting(ctx, collect)
	} else {
		err = collect(ctx)
	}
	// A failed-installed disposal exists to remove a Guest that is often dead,
	// so that Guest cannot prove complete reporting membership. Only the plan
	// step, and only when the intent already carries a requested disposal, may
	// continue with the fully validated inventory, snapshot and demand reads to
	// the claim. Resume and ordinary assessment never run without coverage, and
	// every other operation keeps the strict gate. A gate that cannot answer
	// fails this stage with its own cause instead of hiding behind coverage.
	var coverageErr error
	if err != nil && originalGuestPlanCoverageMayDefer(step.Use.Operation, err) {
		requested, requestedErr := store.WithOriginalGuestReconcile(wf, step, capacity.CurrentGuestCoreSource(), parsed.Mode, parsed.RequestID, inv, reporting).FailedInstalledGuestDisposalRequested(ctx, policy)
		if requestedErr != nil {
			return fail(errors.Join(err, requestedErr))
		}
		if requested {
			coverageErr, err = err, nil
		}
	}
	if err != nil {
		return fail(err)
	}
	store = store.WithOriginalGuestReconcile(wf, step, capacity.CurrentGuestCoreSource(), parsed.Mode, parsed.RequestID, inv, reporting)
	stage = "native_installed_members"
	members, pending, err := store.OriginalGuestReconcileMembers(ctx, policy)
	if err != nil {
		return fail(err)
	}
	if coverageErr != nil && pending {
		stage = "source_assessment"
		return fail(coverageErr)
	}
	var output any
	if step.Use.Operation == capacity.PlanOriginalGuestOperation {
		plan := originalGuestReconcilePlan{Mode: "hold", Reason: "outstanding_original_authority"}
		if !pending {
			stage = "installed_resume_claim"
			disposed, preID, disposalEligible, disposalErr := store.TryClaimFailedInstalledGuestDisposal(ctx, policy, assessment)
			if disposalErr != nil {
				return fail(disposalErr)
			}
			if coverageErr != nil && !disposalEligible {
				// No claim: the coverage refusal stands. The members read above
				// has already committed the enrolled slots' observation refresh.
				stage = "source_assessment"
				return fail(coverageErr)
			}
			var resumed model.CapacityIntent
			eligible := false
			var resumeErr error
			if !disposalEligible {
				resumed, eligible, resumeErr = store.TryResumeInstalledGuest(ctx, policy, assessment)
			}
			if resumeErr != nil {
				return fail(resumeErr)
			}
			if !disposalEligible && !eligible {
				store, resumed, eligible, resumeErr = store.TryClaimInstalledReadinessHandoff(ctx, policy, assessment)
				if resumeErr != nil {
					return fail(resumeErr)
				}
			}
			if !disposalEligible && !eligible {
				store, resumed, eligible, resumeErr = store.TryClaimFailedExpansionTerminalReconcile(ctx, policy, assessment)
				if resumeErr != nil {
					return fail(resumeErr)
				}
			}
			if disposalEligible {
				deadline, e := store.OriginalGuestReconcileLeaseDeadline(ctx, policy, disposed.Generation, disposed.FencingToken, disposed.LeaseOwner)
				if e != nil || captureOriginalGuestReconcileDeadline(ctx, deadline) != nil {
					return fail(errOriginalGuestStep)
				}
				plan.Mode, plan.Reason, plan.Slot, plan.PreregistrationID = "retire", "failed_installed_disposal", repository.FailedInstalledDisposalClaimSlot(disposed), preID
				plan.Generation, plan.FencingToken, plan.LeaseOwner = disposed.Generation, disposed.FencingToken, disposed.LeaseOwner
			} else if eligible {
				deadline, e := store.OriginalGuestReconcileLeaseDeadline(ctx, policy, resumed.Generation, resumed.FencingToken, resumed.LeaseOwner)
				if e != nil || captureOriginalGuestReconcileDeadline(ctx, deadline) != nil {
					return fail(errOriginalGuestStep)
				}
				plan.Mode, plan.Reason = "refresh", "installed_original_readiness_reconcile"
				if resumed.InstalledReadinessHandoff != nil {
					plan.Reason = "installed_readiness_exhausted_handoff"
				}
				if resumed.FailedExpansionTerminalReconcile != nil {
					plan.Reason = "failed_expansion_terminal_readonly_reconcile"
				}
				plan.Generation, plan.FencingToken, plan.LeaseOwner = resumed.Generation, resumed.FencingToken, resumed.LeaseOwner
			} else {
				stage = "ordinary_assessment"
				intent, e := store.AssessOriginalGuest(ctx, policy, assessment)
				if e != nil {
					return fail(e)
				}
				plan.Generation, plan.FencingToken = intent.Generation, intent.FencingToken
				plan.Reason = intent.Decision.Reason
				if intent.Phase == "proposed" && intent.Decision.ExecutionPermitted {
					mode, slot, preID, e := originalGuestNextSlot(p, inv, members, intent.Decision)
					if e != nil {
						return fail(e)
					}
					// Actual source reread immediately before the existing Claim.
					inv, assessment, reporting, e = collectOriginalGuestAssessment(ctx, conn, db, policy, p)
					if e != nil {
						return fail(e)
					}
					store = store.WithOriginalGuestReconcile(wf, step, capacity.CurrentGuestCoreSource(), "", "", inv, reporting)
					fresh, unresolved, e := store.OriginalGuestReconcileMembers(ctx, policy)
					if e != nil || unresolved || !reflect.DeepEqual(fresh, members) {
						return fail(errOriginalGuestStep)
					}
					intent, e = store.Claim(ctx, policy, intent.Generation, assessment)
					if e != nil {
						return fail(e)
					}
					deadline, e := store.OriginalGuestReconcileLeaseDeadline(ctx, policy, intent.Generation, intent.FencingToken, intent.LeaseOwner)
					if e != nil || captureOriginalGuestReconcileDeadline(ctx, deadline) != nil {
						return fail(errOriginalGuestStep)
					}
					plan.Mode, plan.Slot, plan.PreregistrationID = mode, slot, preID
					plan.Generation, plan.FencingToken, plan.LeaseOwner = intent.Generation, intent.FencingToken, intent.LeaseOwner
				} else if intent.Phase == "promoted" || intent.Phase == "reconciled" || intent.Phase == "reconciled_partial" {
					plan.Mode = "refresh"
				}
			}
		}
		output = plan
	} else {
		if pending {
			return fail(repository.ErrCapacityConflict)
		}
		resuming := false
		if parsed.Mode == "refresh" {
			stage = "installed_resume_epoch"
			var epoch model.CapacityIntent
			store, epoch, resuming, err = store.OriginalGuestInstalledResumeEpoch(ctx, policy)
			if err != nil {
				return fail(err)
			}
			if !resuming {
				store, epoch, resuming, err = store.OriginalGuestInstalledReadinessHandoffEpoch(ctx, policy)
				if err != nil {
					return fail(err)
				}
			}
			if !resuming {
				store, epoch, resuming, err = store.OriginalGuestFailedExpansionTerminalReconcileEpoch(ctx, policy)
				if err != nil {
					return fail(err)
				}
			}
			if resuming {
				parsed.Generation, parsed.FencingToken, parsed.LeaseOwner = epoch.Generation, epoch.FencingToken, epoch.LeaseOwner
			}
		}
		stage = "signing_key"
		store = store.WithOriginalGuestNotifyCanary(step, capacity.CurrentGuestCoreSource())
		key, e := sourceGuestSigningKey(ctx, db, p.GuestRetirementBinding.IntentSigningKeyRef)
		if e != nil {
			return fail(e)
		}
		if parsed.Mode != "retire" {
			for _, member := range members {
				if originalGuestReconcileLive(ctx) != nil {
					return fail(errOriginalGuestStep)
				}
				probe := guestOriginalStepInput{Policy: parsed.Policy, BindingName: p.MutationBindings[0].Name, Slot: member.Slot, Generation: parsed.Generation, FencingToken: parsed.FencingToken, LeaseOwner: parsed.LeaseOwner, PreregistrationID: member.PreregistrationID}
				if parsed.Mode == "refresh" && !resuming {
					probe.Generation, probe.FencingToken, probe.LeaseOwner, e = store.GuestNotifyMaintenanceEpoch(ctx, policy, member.PreregistrationID)
					if e != nil {
						return fail(e)
					}
				}
				stage = "fresh_original_canary"
				if _, e = executeOriginalGuestNotifyProbe(ctx, db, store, policy, p, probe, key); e != nil {
					return fail(e)
				}
			}
		}
		if parsed.Mode == "refresh" && !resuming {
			if len(members) < p.Floor {
				return fail(errOriginalGuestStep)
			}
			output = map[string]any{"mode": "refresh", "members": len(members), "provider_mutations": false}
		} else {
			// Refresh source observations after all actual original canaries.
			stage = "post_canary_source_assessment"
			inv, assessment, reporting, e = collectOriginalGuestAssessment(ctx, conn, db, policy, p)
			if e != nil {
				return fail(e)
			}
			effectiveMode := parsed.Mode
			if resuming {
				effectiveMode = "provision"
			}
			store = store.WithOriginalGuestReconcile(wf, step, capacity.CurrentGuestCoreSource(), effectiveMode, parsed.RequestID, inv, reporting)
			phases := []string{"prepared", "canary", "promoted"}
			if parsed.Mode == "retire" {
				// Finish already committed drained from the original V2/off
				// proof before issuing DELETE. Promotion still revalidates the
				// confirmed grant, absence and fresh surviving membership.
				phases = []string{"promoted"}
			}
			var intent model.CapacityIntent
			for _, phase := range phases {
				if originalGuestReconcileLive(ctx) != nil {
					return fail(errOriginalGuestStep)
				}
				stage = "advance_" + phase
				intent, e = store.AdvanceOriginalGuest(ctx, policy, parsed.Generation, parsed.FencingToken, parsed.LeaseOwner, phase, assessment)
				if e != nil {
					return fail(e)
				}
			}
			intent.LeaseOwner, intent.LeaseExecutorID = "", ""
			output = intent
		}
	}
	if originalGuestReconcileLive(ctx) != nil {
		return fail(errOriginalGuestStep)
	}
	raw, err := json.Marshal(output)
	if err != nil || json.Unmarshal(raw, &result.Metadata) != nil {
		return fail(errOriginalGuestStep)
	}
	result.Status, result.Error, result.FinishedAt = "succeeded", "", time.Now().UTC()
	return result
}

// Keep the existing process switch spelling and strict value semantics.
func capacityExecutionEnabled() bool {
	return os.Getenv("YGGDRASIL_CAPACITY_EXECUTION_ENABLED") == "true"
}
