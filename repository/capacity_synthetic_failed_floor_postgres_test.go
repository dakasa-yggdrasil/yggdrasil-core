//go:build recoveryfixture && !nativequalification

package repository

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

// Signed fixture data only, with no physical or provider evidence.
func syntheticFailedFloorSetup(t *testing.T) mutationFixture {
	t.Helper()
	capacity.RecoveryFixtureApprovalScope(t)
	db := recoveryTestIsolatedDB(t)
	var dbName string
	if err := db.QueryRow(`SELECT current_database()`).Scan(&dbName); err != nil {
		t.Fatal(err)
	}
	adminURL, err := url.Parse(os.Getenv("RECOVERY_FIXTURE_ADMIN_URL"))
	if err != nil {
		t.Fatal(err)
	}
	adminURL.Path = "/" + dbName
	t.Setenv("DB_URL", adminURL.String())
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)
	p, b, _, _, _ := capacity.RecoveryFixtureInstalled(t)
	ns := "unit-compensation-" + uuid.NewString()
	now := time.Now().UTC()
	v := 0.9
	generic := model.CapacityPolicySpec{Environment: "production", Domain: "api", Dimension: "replicas", TargetIdentity: "cluster/ns/api", Owner: "capacity-api", MaxEvidenceAgeSeconds: 60, MaxSampleGapSeconds: 30, MinSamples: 3, UpHoldSeconds: 0, DownHoldSeconds: 1, CooldownSeconds: 30, Signals: []model.CapacitySignalRule{{Name: "pressure", SourceIdentity: "prom/api", Unit: "ratio", UpAbove: 0.8, DownBelow: 0.3}}}
	a := model.CapacityAssessment{Snapshot: model.CapacitySnapshot{TargetIdentity: generic.TargetIdentity, ResourceUID: "hpa-1", WorkloadUID: "deployment-1", WorkloadResourceVersion: "10", ResourceVersion: "1", Owner: generic.Owner, Units: 2, ObservedAt: now}, Evidence: []model.CapacityEvidence{{Name: "pressure", SourceIdentity: "prom/api", Unit: "ratio", RequireData: true, Matched: true, DataState: "present", Value: &v, RangeMin: &v, RangeMax: &v, SourceSampledAt: now, WindowStart: now.Add(-time.Minute), WindowEnd: now, Samples: 10, CoverageComplete: true, MaxGapSeconds: 15}}}
	p.Environment, p.Domain, p.Dimension = generic.Environment, generic.Domain, generic.Dimension
	p.TargetIdentity, p.Owner, p.Signals = generic.TargetIdentity, generic.Owner, generic.Signals
	p.MaxEvidenceAgeSeconds, p.MaxSampleGapSeconds, p.MinSamples = generic.MaxEvidenceAgeSeconds, generic.MaxSampleGapSeconds, generic.MinSamples
	p.UpHoldSeconds, p.DownHoldSeconds, p.CooldownSeconds = generic.UpHoldSeconds, generic.DownHoldSeconds, generic.CooldownSeconds
	p.Workflow = model.ManifestSelector{Namespace: ns, Name: "synthetic-guest-workflow"}
	p.Floor, p.Ceiling, p.Step, p.LeaseSeconds = 3, 8, 1, 120
	p.ExecutionEnabled = true
	p.GuestNotifyReconcileBinding = nil
	p.Profiles[0].MinUnits = 3
	p.Profiles[0].QuoteValidUntil = time.Now().UTC().Add(time.Hour)
	p.Profiles[0].ValidationValidUntil = time.Now().UTC().Add(time.Hour)
	a.Snapshot.TargetIdentity = p.TargetIdentity
	a.Snapshot.Owner = p.Owner
	a.Snapshot.Profile = p.Profiles[0].Name
	create := func(kind, name string, spec any) model.Manifest {
		t.Helper()
		wire, e := json.Marshal(spec)
		if e != nil {
			t.Fatal(e)
		}
		m, e := CreateManifestVersion(ctx, db, model.ManifestDocument{APIVersion: "v1", Kind: kind, Metadata: model.ManifestMetadataInput{Namespace: ns, Name: name}, Spec: wire}, capacity.BusinessCreationSHA256(wire))
		if e != nil {
			t.Fatal(e)
		}
		return m
	}
	typSpec := mutationTypeFixture()
	typSpec.Provider = "hetzner"
	typ := create("integration_type", "synthetic-type", typSpec)
	inst := create("integration_instance", "synthetic-instance", map[string]any{"type_ref": model.ManifestSelector{ManifestID: typ.ID.String()}})
	mutation := p.MutationBindings[0]
	mutation.IntegrationInstanceID = inst.ID.String()
	mutation.IntegrationChecksum = inst.Checksum
	mutation.IntegrationTypeID = typ.ID.String()
	mutation.IntegrationTypeChecksum = typ.Checksum
	mutation.ProtectedSlots = 3
	plans := map[int]model.CapacityMutationIssue{}
	for i := range mutation.Slots {
		slot := &mutation.Slots[i]
		slot.DesiredSpec.IntegrationInstanceID = inst.ID.String()
		wire, e := json.Marshal(slot.DesiredSpec)
		if e != nil {
			t.Fatal(e)
		}
		var canonical map[string]any
		if e = json.Unmarshal(wire, &canonical); e != nil {
			t.Fatal(e)
		}
		wire, e = json.Marshal(canonical)
		if e != nil {
			t.Fatal(e)
		}
		slot.DesiredSpecSHA256 = capacity.BusinessCreationSHA256(wire)
		plans[slot.Slot] = model.CapacityMutationIssue{BindingName: mutation.Name, DesiredSpec: wire}
	}
	p.MutationBindings = []model.CapacityMutationBinding{mutation}
	p.GuestRetirementBinding = &b
	if err := capacity.ValidateGuestRetirementBinding(p, &b); err != nil {
		t.Fatal("binding", err)
	}
	if err := capacity.ValidateGuestNotifyCanaryBinding(p); err != nil {
		t.Fatal("canary", err)
	}
	if err := capacity.RegisterRecoveryFixtureApproval(p, b, "hetzner"); err != nil {
		t.Fatal("test approval", err)
	}
	withCleanup := p
	withCleanup.MutationBindings = append([]model.CapacityMutationBinding(nil), p.MutationBindings...)
	withCleanup.MutationBindings[0].CompensationEnabled = true
	if err := capacity.RegisterRecoveryFixtureApproval(withCleanup, b, "hetzner"); err != nil {
		t.Fatal("test cleanup approval", err)
	}
	step := model.WorkflowStepSpec{ID: b.ProfileManifest.OriginalProvisioningStepID, Use: model.WorkflowStepUseSpec{Kind: "yggdrasil", Operation: capacity.ProvisionOriginalGuestOperation}, TimeoutSeconds: b.ProfileManifest.OriginalProvisioningBudgetSeconds}
	wf := create("workflow", p.Workflow.Name, map[string]any{"authorization": map[string]any{"rbac": map[string]string{"namespace": p.Workflow.Namespace, "name": "fixture-rbac"}}, "steps": []model.WorkflowStepSpec{step}})
	policy := create("capacity_policy", "synthetic-guest-policy", p)
	store := CapacityStore{DB: db, ExecutionEnabled: true, WorkflowID: wf.ID, ExecutorID: uuid.NewString()}.WithOriginalGuestProvisioning(step, capacity.CurrentGuestCoreSource(), strings.Repeat("a", 64))
	intent, e := store.Assess(ctx, policy, a)
	if e != nil {
		t.Fatal("assess", e)
	}
	t.Logf("assessed phase=%s action=%s reason=%s units=%d", intent.Phase, intent.Decision.Action, intent.Decision.Reason, intent.Decision.Units)
	intent, e = store.Claim(ctx, policy, intent.Generation, a)
	if e != nil {
		t.Fatal("claim", e)
	}
	f := mutationFixture{db: db, policy: policy, store: store, a: a, intent: intent, binding: mutation, plans: plans, created: time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano)}
	for slot := 1; slot <= 2; slot++ {
		f.record(t, slot)
	}
	return f
}

func TestSyntheticFailedFloorRecoveryPostgres(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	f := syntheticFailedFloorSetup(t)
	if f.intent.Decision.Reason != "protected_floor_recovery" || f.intent.Decision.Units != 3 || f.intent.BaselineSnapshot.Units != 2 {
		t.Fatal("fixture did not admit exact floor repair", f.intent)
	}
	parent, err := f.store.IssueMutation(ctx, f.policy, f.intent.Generation, f.intent.FencingToken, f.intent.LeaseOwner, f.plans[3])
	if err != nil {
		t.Fatal("real IssueMutation", err)
	}
	// The reserved third slot prevents another create from replacing ambiguous
	// native work. Cleanup will remove no registered member from the two-node base.
	if _, err := f.store.IssueMutation(ctx, f.policy, f.intent.Generation, f.intent.FencingToken, f.intent.LeaseOwner, f.plans[4]); !errors.Is(err, ErrCapacityConflict) {
		t.Fatal("ambiguous failed create lost its target reservation", err)
	}
	nonce := uuid.NewString()
	redemption := mutationRedeem(parent, nonce)
	if _, err := f.store.RedeemMutation(ctx, f.binding.AdapterPrincipalID, redemption); err != nil {
		t.Fatal(err)
	}
	settled := mutationSettlement(redemption, f.created)
	instant := time.Now().UTC().Format(time.RFC3339Nano)
	settled.ResourceID, settled.ResourceCreatedAt, settled.ObservedAt = "123", instant, instant
	settled.OriginalProviderCreateReturn = &model.CapacityOriginalProviderCreateReturn{Schema: "hetzner_original_create_return_v1", Provider: "hetzner", AdapterSourceCommit: f.binding.OriginalProviderSourceCommit, GrantID: parent.GrantID, AttemptID: redemption.AttemptID, RequestSHA256: parent.RequestSHA256, ResourceID: settled.ResourceID, ResourceCreatedAt: instant, ActionID: settled.ActionID, NextActionIDs: settled.NextActionIDs, CalledAt: instant, ReturnedAt: instant, ContextDeadline: parent.ExpiresAt.UTC().Format(time.RFC3339Nano), ResponseStatus: 201, ResponseBodySHA256: strings.Repeat("d", 64), ResponseBytes: 100}
	if _, err := f.store.SettleMutation(ctx, f.binding.AdapterPrincipalID, nonce, settled); err != nil {
		t.Fatal(err)
	}
	var pInitial model.CapacityPolicySpec
	if err := json.Unmarshal(f.policy.Spec, &pInitial); err != nil {
		t.Fatal(err)
	}
	b := *pInitial.GuestRetirementBinding
	var preWire []byte
	if err := f.db.QueryRow(`SELECT original_wire FROM public.capacity_vm_provisioning_preregistrations WHERE create_grant_id=$1`, parent.GrantID).Scan(&preWire); err != nil {
		t.Fatal(err)
	}
	var pre model.CapacityGuestOriginalProvisioningPreregistration
	if err := json.Unmarshal(preWire, &pre); err != nil {
		t.Fatal(err)
	}
	witness, reg, receipt := capacity.RecoveryFixtureCompensationRegistration(t, pInitial, b, pre, settled)
	retirementID := syntheticRetirement(t, ctx, f.db, f.store, f.policy, pInitial, b, pre, witness, reg, receipt, f.intent)
	off := map[string]any{"server": map[string]any{"id": settled.ResourceID, "created_at": settled.ResourceCreatedAt, "status": "off", "observed_at": time.Now().UTC().Format(time.RFC3339Nano)}}
	offWire, _ := json.Marshal(off)
	if _, err := f.db.Exec(`INSERT INTO public.capacity_guest_original_native_poweroff_reads(id,intent_id,observation_sha256,original_wire,original_record,recorded_at) VALUES($1,$2,$3,$4,$5::jsonb,clock_timestamp())`, uuid.NewString(), retirementID, capacity.BusinessCreationSHA256(offWire), offWire, string(offWire)); err != nil {
		t.Fatal(err)
	}
	failed := f.proof(t, 3)
	failed.GrantID, failed.ResourceID, failed.ResourceCreatedAt, failed.ObservedCreationGrantID = parent.GrantID, settled.ResourceID, settled.ResourceCreatedAt, parent.GrantID
	failed.ActionsTerminal, failed.ActionsFailed, failed.SpecVerified, failed.CompensationIdentityVerified = true, true, false, true
	failed.ActionIDs = []string{"native-action", "bootstrap-action"}
	var desired model.CapacityMutationSpecV1
	if err := json.Unmarshal(f.plans[3].DesiredSpec, &desired); err != nil {
		t.Fatal(err)
	}
	desired.Capability, desired.ExpectedResourceID, desired.ExpectedResourceCreatedAt = f.binding.DestroyCapability, settled.ResourceID, settled.ResourceCreatedAt
	rawDesired, _ := json.Marshal(desired)
	zero := 0
	drain := model.CapacityTransitionProof{Assessment: freshCapacityTestAssessment(f.a, 2), ObservedAt: time.Now().UTC(), ReceiptRef: "fixture:failed-third-never-routed", Healthy: true, MembershipComplete: true, AdmissionClosed: true, RoutingWithdrawn: true, Inflight: &zero, NativeActionsInflight: &zero}
	issue := model.CapacityCompensationIssue{ParentGrantID: parent.GrantID, Mutation: model.CapacityMutationIssue{BindingName: f.binding.Name, DesiredSpec: rawDesired}, FailedProof: failed, DrainProof: drain}
	expireCapacityTestLease(t, f.db, f.policy.Metadata.Namespace)
	recovery := f.store
	recovery.ExecutionEnabled, recovery.ExecutorID = false, uuid.NewString()
	lease, err := recovery.Recover(ctx, f.policy, f.intent.Generation, freshCapacityTestAssessment(f.a, 2))
	if err != nil {
		t.Fatal(err)
	}
	var p model.CapacityPolicySpec
	if err := json.Unmarshal(f.policy.Spec, &p); err != nil {
		t.Fatal(err)
	}
	p.MutationBindings[0].CompensationEnabled = true
	raw, _ := json.Marshal(p)
	current, err := CreateManifestVersion(ctx, f.db, model.ManifestDocument{APIVersion: f.policy.APIVersion, Kind: f.policy.Kind, Metadata: model.ManifestMetadataInput{Namespace: f.policy.Metadata.Namespace, Name: f.policy.Metadata.Name}, Spec: raw}, fmt.Sprintf("%x", sha256.Sum256(raw)))
	if err != nil {
		t.Fatal(err)
	}
	issuer := f.store
	issuer.ExecutorID = uuid.NewString()
	for _, scenario := range []string{"baseline_lost", "incomplete", "wrong_profile", "native_running", "business_running"} {
		bad := issue
		switch scenario {
		case "baseline_lost":
			bad.DrainProof.Assessment.Snapshot.Units = 1
		case "incomplete":
			bad.DrainProof.MembershipComplete = false
		case "wrong_profile":
			bad.DrainProof.Assessment.Snapshot.Profile = "alternate"
		case "native_running":
			one := 1
			bad.DrainProof.NativeActionsInflight = &one
		case "business_running":
			one := 1
			bad.DrainProof.Inflight = &one
		}
		if _, err := issuer.IssueCompensation(ctx, current, bad); err == nil {
			t.Fatal("degraded cleanup bypassed unchanged healthy baseline", scenario)
		}
	}
	terminal := model.CapacityTransitionProof{Assessment: freshCapacityTestAssessment(f.a, 2), ObservedAt: time.Now().UTC(), ReceiptRef: "fixture:degraded-floor-readback", Healthy: true, MembershipComplete: true, Inflight: &zero, MutationInflight: &zero, MutationAuthorityKind: "core_mutation_grants"}
	if _, err := recovery.Reconcile(ctx, f.policy, lease.Generation, lease.FencingToken, lease.LeaseOwner, "reconciled_failed_floor", terminal); !errors.Is(err, ErrCapacityConflict) {
		t.Fatal("unresolved parent became closed failed repair", err)
	}
	child, err := issuer.IssueCompensation(ctx, current, issue)
	if err != nil || child.ExpectedResourceID != settled.ResourceID || child.CompensationOf != parent.GrantID {
		t.Fatal("failed protected slot could not be cleaned without removing baseline", child, err)
	}
	if _, err := recovery.Reconcile(ctx, f.policy, lease.Generation, lease.FencingToken, lease.LeaseOwner, "reconciled_failed_floor", terminal); !errors.Is(err, ErrCapacityConflict) {
		t.Fatal("unresolved cleanup child released failed repair", err)
	}
	childNonce := uuid.NewString()
	childRedemption := mutationRedeem(child, childNonce)
	if permission, err := issuer.RedeemMutation(ctx, f.binding.AdapterPrincipalID, childRedemption); err != nil || permission.Mode != "write_once" {
		t.Fatal("separate cleanup gate could not redeem belowfloor baseline", permission, err)
	}
	childSettle := mutationSettlement(childRedemption, settled.ResourceCreatedAt)
	childSettle.ResourceID = settled.ResourceID
	if _, err := issuer.SettleMutation(ctx, f.binding.AdapterPrincipalID, childNonce, childSettle); err != nil {
		t.Fatal(err)
	}
	deleted := failed
	deleted.GrantID, deleted.RequestSHA256 = child.GrantID, child.RequestSHA256
	deleted.ActionsSuccessful, deleted.ActionsFailed, deleted.ResourceAbsent = true, false, true
	deleted.AuxiliaryAbsent = []model.CapacityMutationAuxiliaryResource{{Kind: "primary_ip", ID: "ip-fixture"}}
	receiptAfter, e := issuer.MutationReceipt(ctx, f.binding.AdapterPrincipalID, child.GrantID)
	if e != nil {
		t.Fatal(e)
	}
	observedAt := time.Now().UTC().Format(time.RFC3339Nano)
	native := model.CapacityVMRetirementObservation{CapacityVMNativeTuple: model.CapacityVMNativeTuple{ID: child.ExpectedResourceID, CreatedAt: child.ExpectedResourceCreatedAt}, DestroyGrantID: child.GrantID, DestroyGrantState: "settled", CompensationOf: grant.GrantID, OriginalOutcome: "accepted", OriginalTransportCompleted: true, ServerAbsent: true, ServerAbsenceComplete: true, ServerObservedAt: observedAt, DeleteAction: model.CapacityVMRetirementAction{Known: true, Observed: true, ID: childSettle.ActionID, Status: "success", Command: "delete_server", StartedAt: observedAt, FinishedAt: observedAt}, NextActions: []model.CapacityVMActionObservation{{ID: "bootstrap-action", Status: "success", Command: "delete_server", ResourceID: child.ExpectedResourceID, StartedAt: observedAt, FinishedAt: observedAt, ObservedAt: observedAt}}, AuxiliaryResources: []model.CapacityVMAuxiliaryObservation{{Kind: "primary_ip", ID: "ip-fixture", Absent: true, ObservedAt: observedAt}}, AuxiliaryInventoryComplete: true, BillableResourcesAbsent: true, RetirementComplete: true, HoldReasons: []string{}, ObservationStartedAt: observedAt, ObservedAt: observedAt}
	native.BillingExposure = &model.CapacityVMBillingExposure{Basis: "profile_admission_ceiling_not_invoice", Currency: capacity.NativeBillingCurrency(pInitial), WindowStart: child.ExpectedResourceCreatedAt, WindowEndUpperBound: observedAt, WindowEndSource: "native_delete_action_finished", Resources: []model.CapacityVMBillableResourceWindow{{Kind: "server", ID: child.ExpectedResourceID, WindowStart: child.ExpectedResourceCreatedAt, WindowStartSource: "native_server_created_at", WindowEndUpperBound: observedAt, WindowEndSource: "native_delete_action_finished", StartedHoursUpperBound: 1}, {Kind: "primary_ip", ID: "ip-fixture", WindowStart: child.ExpectedResourceCreatedAt, WindowStartSource: "server_creation_proxy_not_native_ip_creation", WindowEndUpperBound: observedAt, WindowEndSource: "first_complete_absence_observation", StartedHoursUpperBound: 1}}, StartedHoursUpperBound: 1, CalendarMonthsUpperBound: 1, ExcludedCosts: []string{"test only"}}
	if e = recovery.RecordVMRetirementReadback(ctx, f.policy, f.intent.Generation, lease.FencingToken, lease.LeaseOwner, native); e != nil {
		t.Fatal("real readback writer", e)
	}
	deleted, e = capacity.VMRetirementProof(pInitial, pInitial.MutationBindings[0], receiptAfter, native, time.Now().UTC(), "fixture:native-read")
	if e != nil {
		t.Fatal("synthetic native proof", e)
	}
	if _, err := issuer.ConfirmCompensation(ctx, current, deleted); err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"baseline_lost", "incomplete", "wrong_profile", "no_mutation"} {
		bad := terminal
		switch scenario {
		case "baseline_lost":
			bad.Assessment.Snapshot.Units = 1
		case "incomplete":
			bad.MembershipComplete = false
		case "wrong_profile":
			bad.Assessment.Snapshot.Profile = "alternate"
		case "no_mutation":
			bad.NoMutationVerified = true
		}
		if _, err := recovery.Reconcile(ctx, f.policy, lease.Generation, lease.FencingToken, lease.LeaseOwner, "reconciled_failed_floor", bad); err == nil {
			t.Fatal("failed floor readback accepted invalid outcome", scenario)
		}
	}
	if _, err := recovery.Reconcile(ctx, f.policy, lease.Generation, lease.FencingToken, lease.LeaseOwner, "reconciled_partial", terminal); err == nil {
		t.Fatal("ordinary partial recovery claimed protected floor below3")
	}
	terminal.NoMutationVerified = true
	if _, err := recovery.Reconcile(ctx, f.policy, lease.Generation, lease.FencingToken, lease.LeaseOwner, "aborted", terminal); err == nil {
		t.Fatal("compensated floor repair became no-mutation abort")
	}
	terminal.NoMutationVerified = false
	finished, err := recovery.Reconcile(ctx, f.policy, lease.Generation, lease.FencingToken, lease.LeaseOwner, "reconciled_failed_floor", terminal)
	if err != nil || finished.Phase != "reconciled_failed_floor" || !finished.FloorDegraded || finished.Assessment.Snapshot.Units != 2 || finished.Decision.Units != 3 || finished.Decision.ExecutionPermitted || finished.LeaseOwner != "" {
		t.Fatal("failed floor did not close truthfully", finished, err)
	}
	// The next explicit floor repair bypasses ordinary cooldown without turning
	// the closed historical recovery epoch back into write authority.
	nextStore := issuer
	nextStore.ExecutorID = uuid.NewString()
	next, err := nextStore.Assess(ctx, current, freshCapacityTestAssessment(f.a, 2))
	if err != nil || next.Generation != lease.Generation+1 || next.Decision.Reason != "protected_floor_recovery" || next.Decision.Units != 3 || next.FloorDegraded {
		t.Fatal("failed floor deadlocked next independent repair", next, err)
	}
	next, err = nextStore.Claim(ctx, current, next.Generation, freshCapacityTestAssessment(f.a, 2))
	if err != nil {
		t.Fatal(err)
	}
	replacement, err := nextStore.IssueMutation(ctx, current, next.Generation, next.FencingToken, next.LeaseOwner, f.plans[3])
	if err != nil || replacement.GrantID == parent.GrantID || replacement.CompensationOf != "" {
		t.Fatal("new floor repair could not reserve a fresh create", replacement, err)
	}
}
