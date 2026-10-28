//go:build recoveryfixture && !nativequalification

package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// All witness/enrollment/retirement data are synthetic and confined to a
// newly created local PG16 database. This supplies no native/provider proof.
func TestSyntheticFloorDrainBudgetPostgres(t *testing.T) {
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
	defer cancel()
	p, b, _, _, _ := capacity.RecoveryFixtureInstalled(t)
	b.CoreAuthoritySourceCommit = capacity.CurrentGuestCoreSource()
	if b.CoreAuthoritySourceCommit == "" {
		t.Fatal("clean source identity required")
	}
	ns := "unit-compensation-" + uuid.NewString()
	now := time.Now().UTC()
	v := 0.9
	generic := model.CapacityPolicySpec{Environment: "production", Domain: "api", Dimension: "replicas", TargetIdentity: "cluster/ns/api", Owner: "capacity-api", MaxEvidenceAgeSeconds: 60, MaxSampleGapSeconds: 30, MinSamples: 3, UpHoldSeconds: 0, DownHoldSeconds: 1, CooldownSeconds: 30, Signals: []model.CapacitySignalRule{{Name: "pressure", SourceIdentity: "prom/api", Unit: "ratio", UpAbove: 0.8, DownBelow: 0.3}}}
	a := model.CapacityAssessment{Snapshot: model.CapacitySnapshot{TargetIdentity: generic.TargetIdentity, ResourceUID: "hpa-1", WorkloadUID: "deployment-1", WorkloadResourceVersion: "10", ResourceVersion: "1", Owner: generic.Owner, Units: 4, ObservedAt: now}, Evidence: []model.CapacityEvidence{{Name: "pressure", SourceIdentity: "prom/api", Unit: "ratio", RequireData: true, Matched: true, DataState: "present", Value: &v, RangeMin: &v, RangeMax: &v, SourceSampledAt: now, WindowStart: now.Add(-time.Minute), WindowEnd: now, Samples: 10, CoverageComplete: true, MaxGapSeconds: 15}}}
	p.Environment, p.Domain, p.Dimension = generic.Environment, generic.Domain, generic.Dimension
	p.TargetIdentity, p.Owner, p.Signals = generic.TargetIdentity, generic.Owner, generic.Signals
	p.MaxEvidenceAgeSeconds, p.MaxSampleGapSeconds, p.MinSamples = generic.MaxEvidenceAgeSeconds, generic.MaxSampleGapSeconds, generic.MinSamples
	p.UpHoldSeconds, p.DownHoldSeconds, p.CooldownSeconds = generic.UpHoldSeconds, generic.DownHoldSeconds, generic.CooldownSeconds
	p.Workflow = model.ManifestSelector{Namespace: ns, Name: "synthetic-guest-workflow"}
	p.Floor, p.Ceiling, p.Step, p.LeaseSeconds = 2, 8, 2, 120
	p.ExecutionEnabled = true
	p.GuestNotifyReconcileBinding = nil
	// This independent, explicitly synthetic writer is not the Notify singleton.
	p.GuestNotifyCanaryBinding = nil
	b.ProfileManifest.Writers[0].CgroupRelativePath = b.ProfileManifest.Writers[0].ID
	b.ProfileManifestSHA256 = capacity.GuestRetirementSHA(b.ProfileManifest)
	p.Profiles[0].MinUnits = 2
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
	mutation.ProtectedSlots = 2
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
	if err := capacity.RegisterRecoveryFixtureApproval(p, b, "hetzner"); err != nil {
		t.Fatal("test approval", err)
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
	// Baseline rows and all retirements below are declared test operands.
	for slot := 1; slot <= 4; slot++ {
		observed := f.proof(t, slot)
		if slot >= 3 {
			observed.ResourceID = fmt.Sprintf("%d", 100+slot)
		}
		if e := f.store.RecordMutationSlot(ctx, f.policy, f.intent.Generation, f.intent.FencingToken, f.intent.LeaseOwner, f.plans[slot], observed); e != nil {
			t.Fatal("synthetic baseline", e)
		}
	}
	f.intent.Decision.Action, f.intent.Decision.Units, f.intent.Phase = "drain", 2, "draining"
	intentWire, _ := json.Marshal(f.intent)
	if _, e := db.ExecContext(ctx, `UPDATE public.capacity_intents SET intent=$2::jsonb WHERE namespace=$1`, ns, intentWire); e != nil {
		t.Fatal(e)
	}
	for _, slot := range []int{3, 4} {
		reserved := time.Now().UTC().Truncate(time.Microsecond).Add(-2 * time.Second)
		pre := model.CapacityGuestOriginalProvisioningPreregistration{
			Schema: capacity.GuestPreregistrationSchema, PreregistrationID: uuid.NewString(), BindingName: b.Members[slot-1].Name,
			OriginalCreateGrantID: uuid.NewString(), OriginalCreateRequestSHA256: strings.Repeat("a", 64), NonceSHA256: capacity.BusinessCreationSHA256([]byte(uuid.NewString())),
			ProfileManifestSHA256: b.ProfileManifestSHA256, PolicyID: policy.ID.String(), PolicyChecksum: policy.Checksum,
			WorkflowID: wf.ID.String(), WorkflowChecksum: wf.Checksum, OriginalWorkflowStepID: step.ID,
			OriginalWorkflowStepTimeoutSeconds: step.TimeoutSeconds, OriginalWorkflowContextDeadline: reserved.Add(time.Duration(step.TimeoutSeconds) * time.Second),
			CoreSourceCommit: capacity.CurrentGuestCoreSource(), Generation: intent.Generation, Fence: intent.FencingToken,
			LeaseOwner: intent.LeaseOwner, ExecutorID: store.ExecutorID, Slot: slot, ReservedAt: reserved,
			OriginalDeadline: reserved.Add(time.Duration(b.ProfileManifest.OriginalProvisioningBudgetSeconds) * time.Second),
		}
		preWire, _ := json.Marshal(pre)
		bindingWire, _ := json.Marshal(b)
		tx, e := db.BeginTx(ctx, nil)
		if e != nil {
			t.Fatal(e)
		}
		guestOriginalStoragePre(t, tx, ctx, guestOriginalStorageFixture{pre: pre, binding: b, wire: preWire, bindingWire: bindingWire}, preWire, preWire, pre.OriginalDeadline)
		if e = tx.Commit(); e != nil {
			t.Fatal(e)
		}
		at := reserved.Add(time.Second).Format(time.RFC3339Nano)
		settle := model.CapacityMutationSettleRequest{GrantID: pre.OriginalCreateGrantID, AttemptID: uuid.NewString(), RequestSHA256: pre.OriginalCreateRequestSHA256, Outcome: "accepted", TransportCompleted: true, ResourceID: fmt.Sprintf("%d", 100+slot), ResourceCreatedAt: f.created, ActionID: "native-action", ObservedAt: at, OriginalProviderCreateReturn: &model.CapacityOriginalProviderCreateReturn{ReturnedAt: at}}
		witness, reg, receipt := capacity.RecoveryFixtureCompensationRegistration(t, p, b, pre, settle)
		retirementID := syntheticRetirement(t, ctx, db, store, policy, p, b, pre, witness, reg, receipt, f.intent)
		off, _ := json.Marshal(map[string]any{"server": map[string]any{"id": settle.ResourceID, "created_at": settle.ResourceCreatedAt, "status": "off", "observed_at": time.Now().UTC().Format(time.RFC3339Nano)}})
		if _, e := db.ExecContext(ctx, `INSERT INTO public.capacity_guest_original_native_poweroff_reads(id,intent_id,observation_sha256,original_wire,original_record,recorded_at) VALUES($1,$2,$3,$4,$5::jsonb,clock_timestamp())`, uuid.NewString(), retirementID, capacity.BusinessCreationSHA256(off), off, string(off)); e != nil {
			t.Fatal("synthetic off operand", e)
		}
	}
	destroy := func(slot int) model.CapacityMutationIssue {
		var spec map[string]any
		if e := json.Unmarshal(f.plans[slot].DesiredSpec, &spec); e != nil {
			t.Fatal(e)
		}
		spec["capability"] = f.binding.DestroyCapability
		if slot >= 3 {
			spec["expected_resource_id"] = fmt.Sprintf("%d", 100+slot)
		} else {
			spec["expected_resource_id"] = fmt.Sprintf("resource-%d", slot)
		}
		spec["expected_resource_created_at"] = f.created
		wire, _ := json.Marshal(spec)
		return model.CapacityMutationIssue{BindingName: f.binding.Name, DesiredSpec: wire}
	}
	if _, e := store.IssueMutation(ctx, policy, 1, f.intent.FencingToken, f.intent.LeaseOwner, destroy(4)); !errors.Is(e, ErrCapacityConflict) {
		t.Fatal("undrained delete admitted", e)
	}
	proof := model.CapacityTransitionProof{Assessment: f.a, ObservedAt: time.Now().UTC(), ReceiptRef: "synthetic:drain", Healthy: true, Inflight: capacityTestCount(0)}
	if _, e := store.Advance(ctx, policy, 1, f.intent.FencingToken, f.intent.LeaseOwner, "drained", proof); e != nil {
		t.Fatal("advance", e)
	}
	if _, e := store.IssueMutation(ctx, policy, 1, f.intent.FencingToken, f.intent.LeaseOwner, destroy(2)); e == nil {
		t.Fatal("floor deletion admitted")
	}
	g, e := store.IssueMutation(ctx, policy, 1, f.intent.FencingToken, f.intent.LeaseOwner, destroy(4))
	if e != nil {
		t.Fatal("first delete", e)
	}
	if _, e = store.IssueMutation(ctx, policy, 1, f.intent.FencingToken, f.intent.LeaseOwner, destroy(3)); e != nil {
		t.Fatal("second delete", e)
	}
	nonce := uuid.NewString()
	redeem := mutationRedeem(g, nonce)
	if _, e = store.RedeemMutation(ctx, mutation.AdapterPrincipalID, redeem); e != nil {
		t.Fatal(e)
	}
	settle := mutationSettlement(redeem, f.created)
	settle.ResourceID = g.ExpectedResourceID
	if _, e = store.SettleMutation(ctx, mutation.AdapterPrincipalID, nonce, settle); e != nil {
		t.Fatal(e)
	}
	// Synthetic provider observation: no adapter, native process, or provider
	// was contacted. Store still verifies the exact tuple and readback chain.
	receipt, e := store.NativeMutationReceipt(ctx, policy, mutation, g.GrantID)
	if e != nil {
		t.Fatal("synthetic receipt", e)
	}
	base := time.Now().UTC().Add(-100 * time.Millisecond)
	stamp := func(d time.Duration) string { return base.Add(d).Format(time.RFC3339Nano) }
	end := stamp(0)
	observation := model.CapacityVMRetirementObservation{
		CapacityVMNativeTuple: model.CapacityVMNativeTuple{ID: g.ExpectedResourceID, CreatedAt: g.ExpectedResourceCreatedAt},
		DestroyGrantID:        g.GrantID, DestroyGrantState: "settled", OriginalOutcome: "accepted", OriginalTransportCompleted: true,
		ServerAbsent: true, ServerAbsenceComplete: true, ServerObservedAt: stamp(-200 * time.Millisecond),
		DeleteAction:               model.CapacityVMRetirementAction{Known: true, Observed: true, ID: settle.ActionID, Status: "success", Command: "delete_server", StartedAt: stamp(-time.Second), FinishedAt: stamp(-500 * time.Millisecond)},
		NextActions:                []model.CapacityVMActionObservation{{ID: settle.NextActionIDs[0], Status: "success", Command: "delete_server", ResourceID: g.ExpectedResourceID, StartedAt: stamp(-800 * time.Millisecond), FinishedAt: stamp(-400 * time.Millisecond), ObservedAt: end}},
		AuxiliaryResources:         []model.CapacityVMAuxiliaryObservation{{Kind: "primary_ip", ID: "ip-fixture", Absent: true, ObservedAt: stamp(-100 * time.Millisecond)}},
		AuxiliaryInventoryComplete: true, BillableResourcesAbsent: true, RetirementComplete: true, HoldReasons: []string{}, ObservationStartedAt: stamp(-300 * time.Millisecond), ObservedAt: end,
	}
	observation.BillingExposure = &model.CapacityVMBillingExposure{Basis: "profile_admission_ceiling_not_invoice", Currency: capacity.NativeBillingCurrency(p), WindowStart: f.created, WindowEndUpperBound: stamp(-100 * time.Millisecond), WindowEndSource: "first_complete_absence_observation", Resources: []model.CapacityVMBillableResourceWindow{
		{Kind: "server", ID: g.ExpectedResourceID, WindowStart: f.created, WindowStartSource: "native_server_created_at", WindowEndUpperBound: stamp(-500 * time.Millisecond), WindowEndSource: "native_delete_action_finished", StartedHoursUpperBound: 2},
		{Kind: "primary_ip", ID: "ip-fixture", WindowStart: f.created, WindowStartSource: "server_creation_proxy_not_native_ip_creation", WindowEndUpperBound: stamp(-100 * time.Millisecond), WindowEndSource: "first_complete_absence_observation", StartedHoursUpperBound: 2},
	}, StartedHoursUpperBound: 2, CalendarMonthsUpperBound: 1, GrossHourlyCeilingMicros: 1000, GrossMonthlyCeilingMicros: 2000, HourlyCeilingTotalMicros: 2000, MonthlyCapCeilingTotalMicros: 2000, GrossCeilingMicrosUpperBound: 2000, IncludesPrimaryIPv4: true, ExcludedCosts: []string{"synthetic, not an invoice"}}
	if e = store.RecordVMRetirementReadback(ctx, policy, 1, f.intent.FencingToken, f.intent.LeaseOwner, observation); e != nil {
		t.Fatal("record synthetic readback", e)
	}
	deleted, e := capacity.VMRetirementProof(p, mutation, receipt, observation, time.Now().UTC(), "synthetic:no-provider-read")
	if e != nil {
		t.Fatal("synthetic readback proof", e)
	}
	missingAux := deleted
	missingAux.AuxiliaryAbsent = nil
	if _, e = store.ConfirmMutation(ctx, policy, 1, f.intent.FencingToken, f.intent.LeaseOwner, missingAux); !errors.Is(e, ErrCapacityConflict) {
		t.Fatal("unobserved paid auxiliary disappearance", e)
	}
	if _, e = store.ConfirmMutation(ctx, policy, 1, f.intent.FencingToken, f.intent.LeaseOwner, deleted); e != nil {
		t.Fatal("confirm", e)
	}

	var applied int
	if e = db.QueryRowContext(ctx, `SELECT count(*) FROM public.event_log WHERE idempotency_key=$1 AND type='hetzner.server.destroyed' AND payload->>'resource_id'=$2`, "capacity-mutation/"+g.GrantID, deleted.ResourceID).Scan(&applied); e != nil || applied != 1 {
		t.Fatal("canonical deletion event", applied, e)
	}
	observed := f.proof(t, 4)
	observed.ResourceID = "104"
	if e = store.RecordMutationSlot(ctx, policy, 1, f.intent.FencingToken, f.intent.LeaseOwner, f.plans[4], observed); !errors.Is(e, ErrCapacityConflict) {
		t.Fatal("tombstone silently readopted", e)
	}

}
