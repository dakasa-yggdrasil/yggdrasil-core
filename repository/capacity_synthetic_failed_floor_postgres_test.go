//go:build recoveryfixture && !nativequalification

package repository

import (
	"context"
	"encoding/json"
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
	f := syntheticFailedFloorSetup(t)
	if f.intent.Decision.Reason != "protected_floor_recovery" || f.intent.Decision.Units != 3 || f.intent.BaselineSnapshot.Units != 2 {
		t.Fatal("fixture did not admit exact floor repair", f.intent.Decision)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	if _, err := f.store.IssueMutation(ctx, f.policy, f.intent.Generation, f.intent.FencingToken, f.intent.LeaseOwner, f.plans[3]); err != nil {
		t.Fatal(err)
	}
}
