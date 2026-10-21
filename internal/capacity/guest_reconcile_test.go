package capacity

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// Declared synthetic shape/graph fixtures only. No production approval,
// SQL authority, provider create, native inventory or useful receipt is made.
func guestReconcileUnit(t *testing.T) (model.Manifest, model.CapacityPolicySpec, model.CapacityVMFleetInventory, time.Time) {
	t.Helper()
	p, r, _, _ := guestProductionRegistryFixture(t)
	name := "notify-aws-elastic"
	now := time.Now().UTC()
	p.Environment, p.Domain, p.Dimension, p.TargetIdentity, p.Owner = "production", "notify", "original_notify_aws_vm_members", "dakasa-production/"+name, "unit-owner"
	p.Workflow = model.ManifestSelector{Namespace: "dakasa-production", Name: name + "-capacity"}
	p.Floor, p.Ceiling, p.Step, p.MaxEvidenceAgeSeconds = 1, 8, 1, 90
	p.Signals = []model.CapacitySignalRule{{Name: "demand", SourceIdentity: "unit/prometheus/source", Unit: "messages", UpAbove: 10, DownBelow: 1}}
	p.Profiles = []model.CapacityProfile{{Name: name, Provider: "aws", Region: "unit-region", MinUnits: 1, MaxUnits: 8}}
	b := &p.MutationBindings[0]
	b.Name, b.ProfileName, b.MaxSlots = name, name, 8
	b.IntegrationInstanceID = uuid.NewString()
	b.IntegrationTypeID, b.IntegrationTypeChecksum = uuid.NewString(), strings.Repeat("d", 64)
	b.IntegrationChecksum, b.AdapterPrincipalID = strings.Repeat("9", 64), "declared-unit-only-adapter"
	b.ScopeChecksum = strings.Repeat("a", 64)
	b.EnsureCapability, b.DestroyCapability = "ensure_ec2_instance", "destroy_ec2_instance"
	b.Slots = nil
	r.MutationBindingName = name
	r.ProfileManifest.Profile, r.ProfileManifest.MutationBinding = name, name
	r.ProfileManifest.OriginalProvisioningStepID = "provision-original-notify"
	r.ProfileManifest.Writers[0].ID = "notify-original-writer"
	r.ProfileManifest.Writers[0].CgroupRelativePath = "."
	r.ProfileManifest.NotifyCanaryTopology = &model.CapacityGuestNotifyCanaryTopology{Schema: "notify_guest_canary_topology_v1", Namespace: "dakasa-production", Binding: name, DefinitionsSHA256: strings.Repeat("e", 64)}
	r.Members = nil
	for slot := 1; slot <= 8; slot++ {
		spec := &model.CapacityMutationSpecV1{SchemaVersion: "capacity_vm_slot_v1", Capability: b.EnsureCapability, IntegrationInstanceID: b.IntegrationInstanceID, ScopeChecksum: b.ScopeChecksum, ProfileName: name, ProfileChecksum: strings.Repeat("b", 64), AdmissionChecksum: strings.Repeat("c", 64), Slot: slot, NativeName: fmt.Sprintf("unit-%d", slot), BootstrapSHA256: r.ProfileManifest.BootstrapSHA256}
		canonical, err := canonicalMutationProjection(*spec)
		if err != nil {
			t.Fatal(err)
		}
		b.Slots = append(b.Slots, model.CapacityMutationSlotBinding{Slot: slot, DesiredSpec: spec, DesiredSpecSHA256: fmt.Sprintf("%x", sha256.Sum256(canonical))})
		r.Members = append(r.Members, model.CapacityGuestRetirementMemberBinding{Name: fmt.Sprintf("unit-%d", slot), Slot: slot, Origin: fmt.Sprintf("https://unit%d.invalid", slot), ServerCARef: "secret://unit/ca#value", ClientCertificateRef: "secret://unit/cert#value", ClientKeyRef: "secret://unit/key#value", ActorClientPrincipal: fmt.Sprintf("actor-%d", slot), ProvisionerClientPrincipal: fmt.Sprintf("provisioner-%d", slot)})
		r.ProfileManifest.NotifyCanaryTopology.Queues = append(r.ProfileManifest.NotifyCanaryTopology.Queues, model.CapacityGuestNotifyCanaryQueue{Provider: "aws", Slot: slot, Name: fmt.Sprintf("notify.guest-canary.dakasa-production.%s.aws.s%d.q", name, slot)})
	}
	p.GuestNotifyCanaryBinding = &model.CapacityGuestNotifyCanaryBinding{Mode: "original_guest_notify_canary_v1", Name: "unit-only", WriterID: r.ProfileManifest.Writers[0].ID, NotifySourceCommit: r.ProfileManifest.Writers[0].SourceCommit, QuerySHA256: GuestNotifyBusinessQuerySHA256, RecipientSHA256: strings.Repeat("f", 64), RecipientCount: 2, Database: "unit-only", DatabaseOID: "10", SystemID: "20", TableOIDs: []string{"30", "40", "50", "60"}, MinimumPublicationIntervalSeconds: 10, MaximumPublicationsPerHour: 120, TopologySHA256: GuestRetirementSHA(r.ProfileManifest.NotifyCanaryTopology)}
	r.ProfileManifestSHA256 = GuestRetirementSHA(r.ProfileManifest)
	p.GuestRetirementBinding = &r
	p.GuestNotifyReconcileBinding = &model.CapacityGuestNotifyReconcileBinding{Mode: GuestNotifyReconcileMode, Signals: []model.CapacityMetricSignalBinding{{Name: "demand", BindingName: "unit-demand", BindingSHA256: strings.Repeat("1", 64), Adapter: model.CapacityObservationAdapterBinding{IntegrationInstanceID: uuid.NewString(), InstanceChecksum: strings.Repeat("2", 64), IntegrationTypeID: uuid.NewString(), TypeChecksum: strings.Repeat("3", 64)}}}}
	coverage := p.GuestNotifyReconcileBinding.Signals[0]
	coverage.Name, coverage.BindingName = OriginalGuestMemberCoverageName, "unit-member-coverage"
	p.GuestNotifyReconcileBinding.MemberCoverage = &coverage
	if err := ValidateGuestNotifyReconcileBinding(p); err != nil {
		t.Fatal("synthetic source shape", err)
	}
	inv := model.CapacityVMFleetInventory{IntegrationInstanceID: b.IntegrationInstanceID, ScopeChecksum: b.ScopeChecksum, ProfileChecksum: b.Slots[0].DesiredSpec.ProfileChecksum, AdmissionChecksum: b.Slots[0].DesiredSpec.AdmissionChecksum, ProfileName: name, MaxSlots: 8, Complete: true, ObservationStartedAt: now.Add(-time.Second).Format(time.RFC3339Nano), ObservedAt: now.Format(time.RFC3339Nano), Members: []model.CapacityVMFleetInventoryMember{}, MissingSlots: []int{1, 2, 3, 4, 5, 6, 7, 8}}
	policy := model.Manifest{ID: uuid.New(), Kind: "capacity_policy", Metadata: model.ManifestMetadata{Namespace: "dakasa-production", Name: name}, Checksum: strings.Repeat("4", 64)}
	return policy, p, inv, now
}

func TestOriginalGuestReconcileObservationWaitKeepsOriginalBudget(t *testing.T) {
	t.Run("quality_only_same_context", func(t *testing.T) {
		ctx, stop := context.WithTimeout(context.Background(), 2*time.Second)
		defer stop()
		deadline, _ := ctx.Deadline()
		calls := 0
		err := AwaitOriginalGuestReporting(ctx, func(actual context.Context) error {
			calls++
			d, _ := actual.Deadline()
			if actual != ctx || !d.Equal(deadline) {
				t.Fatal("observer renewed the original")
			}
			if calls == 1 {
				return ErrOriginalGuestReportingIncomplete
			}
			return nil
		})
		if err != nil || calls != 2 {
			t.Fatal("bounded quality observation failed", err, calls)
		}
	})
	t.Run("foreign_source_not_retried", func(t *testing.T) {
		ctx, stop := context.WithTimeout(context.Background(), time.Second)
		defer stop()
		calls := 0
		if AwaitOriginalGuestReporting(ctx, func(context.Context) error { calls++; return fmt.Errorf("foreign source") }) == nil || calls != 1 {
			t.Fatal("foreign identity retried")
		}
	})
	t.Run("expiry_does_not_start_another_read", func(t *testing.T) {
		ctx, stop := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer stop()
		calls := 0
		if AwaitOriginalGuestReporting(ctx, func(context.Context) error { calls++; return ErrOriginalGuestReportingIncomplete }) == nil || calls != 1 {
			t.Fatal("expired owner read again")
		}
	})
	t.Run("unbounded_never_reads", func(t *testing.T) {
		calls := 0
		if AwaitOriginalGuestReporting(context.Background(), func(context.Context) error { calls++; return nil }) == nil || calls != 0 {
			t.Fatal("unbounded observation accepted")
		}
	})
}

func TestOriginalGuestReconcileCoverageRejectsPartialAggregates(t *testing.T) {
	for _, name := range []string{"complete", "missing", "partial", "window_partial", "extra", "fraction", "stale", "gap", "sparse", "incomplete", "foreign_binding", "foreign_source", "missing_native0", "invalid_native0"} {
		t.Run(name, func(t *testing.T) {
			_, p, _, now := guestReconcileUnit(t)
			p.MinSamples, p.MaxSampleGapSeconds = 2, 30
			b := p.GuestNotifyReconcileBinding.MemberCoverage
			value, low, high := 2.0, 2.0, 2.0
			r := model.CapacityMetricRangeObservation{CapacityEvidence: model.CapacityEvidence{Name: OriginalGuestMemberCoverageName, SourceIdentity: "production/notify/aws/reporting-members", Unit: "members", RequireData: true, Matched: true, DataState: "present", Value: &value, RangeMin: &low, RangeMax: &high, SourceSampledAt: now, WindowStart: now.Add(-time.Minute), WindowEnd: now, Samples: 5, CoverageComplete: true, MaxGapSeconds: 15}, Operation: ObserveMetricRange, Binding: b.BindingName, BindingSHA256: b.BindingSHA256, EvaluatedAt: now, OK: true, Reason: "complete"}
			native := 2
			switch name {
			case "missing", "missing_native0", "invalid_native0":
				r.DataState, r.Reason, r.OK, r.Matched, r.CoverageComplete, r.Samples = "missing", "missing", false, false, false, 0
				r.Value, r.RangeMin, r.RangeMax = nil, nil, nil
				if name != "missing" {
					native = 0
				}
				if name == "invalid_native0" {
					r.DataState = "invalid"
				}
			case "partial":
				value, low, high = 1, 1, 1
			case "window_partial":
				low = 1
			case "extra":
				value, low, high = 3, 3, 3
			case "fraction":
				value, low, high = 1.5, 1.5, 1.5
			case "stale":
				r.SourceSampledAt = now.Add(-2 * time.Minute)
			case "gap":
				r.MaxGapSeconds = 31
			case "sparse":
				r.Samples = 1
			case "incomplete":
				r.CoverageComplete = false
				r.OK = false
			case "foreign_binding":
				r.BindingSHA256 = strings.Repeat("0", 64)
			case "foreign_source":
				r.SourceIdentity = "production/notify/hetzner/reporting-members"
			}
			if (GuestReconcileMemberCoverage(p, r, native, now) == nil) != (name == "complete" || name == "missing_native0") {
				t.Fatal("partial or foreign reporting count became native membership authority")
			}
		})
	}
}

func TestOriginalGuestReconcileBindingClosedScope(t *testing.T) {
	for _, name := range []string{"valid", "no_mode", "HPA", "qemu", "floor0", "floor2", "ceiling9", "step2", "provider", "dimension", "namespace", "target", "missing_signal", "foreign_signal", "duplicate_signal", "unpinned_adapter", "unpinned_binding", "missing_member", "missing_slot", "bad_profile"} {
		t.Run(name, func(t *testing.T) {
			_, p, _, _ := guestReconcileUnit(t)
			switch name {
			case "no_mode":
				p.GuestNotifyReconcileBinding.Mode = ""
			case "HPA":
				p.AssessmentBinding = &model.CapacityBoundAssessmentBinding{}
			case "qemu":
				p.GuestRetirementBinding.EvidenceClass = "native_qemu_qualification"
			case "floor0":
				p.Floor = 0
			case "floor2":
				p.Floor = 2
			case "ceiling9":
				p.Ceiling = 9
			case "step2":
				p.Step = 2
			case "provider":
				p.Profiles[0].Provider = "other"
			case "dimension":
				p.Dimension = "replicas"
			case "namespace":
				p.Workflow.Namespace = "other"
			case "target":
				p.TargetIdentity = "other"
			case "missing_signal":
				p.GuestNotifyReconcileBinding.Signals = nil
			case "foreign_signal":
				p.GuestNotifyReconcileBinding.Signals[0].Name = "other"
			case "duplicate_signal":
				p.GuestNotifyReconcileBinding.Signals = append(p.GuestNotifyReconcileBinding.Signals, p.GuestNotifyReconcileBinding.Signals[0])
			case "unpinned_adapter":
				p.GuestNotifyReconcileBinding.Signals[0].Adapter.InstanceChecksum = ""
			case "unpinned_binding":
				p.GuestNotifyReconcileBinding.Signals[0].BindingSHA256 = ""
			case "missing_member":
				p.GuestRetirementBinding.Members = p.GuestRetirementBinding.Members[:7]
			case "missing_slot":
				p.MutationBindings[0].Slots = p.MutationBindings[0].Slots[:7]
			case "bad_profile":
				p.GuestRetirementBinding.ProfileManifestSHA256 = strings.Repeat("9", 64)
			}
			if (ValidateGuestNotifyReconcileBinding(p) == nil) != (name == "valid") {
				t.Fatal("scope widened", name)
			}
		})
	}
	if ValidateGuestNotifyReconcileBinding(model.CapacityPolicySpec{}) != nil {
		t.Fatal("legacy nil changed")
	}
}

func TestOriginalGuestReconcileFloorCreationDoesNotInventReadiness(t *testing.T) {
	policy, p, inv, now := guestReconcileUnit(t)
	p.Currency, p.MinSamples, p.MaxSampleGapSeconds, p.DownHoldSeconds, p.LeaseSeconds = "USD", 2, 30, 120, 300
	p.ExecutionEnabled = true
	p.Profiles[0].ValidationRef = "declared-unit-only"
	p.Profiles[0].QuoteValidUntil, p.Profiles[0].ValidationValidUntil = now.Add(time.Hour), now.Add(time.Hour)
	snapshot, err := GuestReconcileSnapshot(policy, p, inv, now)
	if err != nil {
		t.Fatal(err)
	}
	a := model.CapacityAssessment{Snapshot: snapshot}
	decision, err := Assess(p, a, model.CapacityClockState{}, now)
	if err != nil || decision.Reason != "protected_floor_recovery" || decision.Units != 1 || !decision.ExecutionPermitted {
		t.Fatalf("empty demand blocked actual inventory floor repair: %+v %v", decision, err)
	}
	// Presence alone cannot certify the new member or ordinary demand. The
	// original Native/Notify joins are additional guards in the repository.
	a.Snapshot.Units = 1
	if ValidateAssessment(p, a, now) == nil {
		t.Fatal("missing demand became readiness")
	}
	decision, err = Assess(p, a, model.CapacityClockState{}, now)
	if err != nil || decision.Action != "hold" || decision.ExecutionPermitted {
		t.Fatal("absent demand became a scale or retirement instruction", err)
	}
}

func TestOriginalGuestReconcileGraphRejectsCallerAuthority(t *testing.T) {
	for _, name := range []string{"valid", "operation", "for_each", "retry", "timeout", "condition", "caller_assessment", "caller_lease", "disabled", "actorless", "hidden_step", "missing_phase", "changed_scope"} {
		t.Run(name, func(t *testing.T) {
			policy, p, _, _ := guestReconcileUnit(t)
			steps, err := OriginalGuestReconcileGraph(policy, p)
			if err != nil {
				t.Fatal(err)
			}
			enabled, no := true, false
			spec := model.WorkflowManifestSpec{Trigger: model.WorkflowTriggerSpec{Mode: "schedule", Enabled: &enabled, Schedule: &model.WorkflowScheduleTriggerSpec{CronExpression: "* * * * *", CatchupPolicy: "skip"}}, Authorization: &model.WorkflowAuthorizationSpec{RBAC: model.ManifestSelector{Namespace: "dakasa-production", Name: "unit-rbac"}}, DispatchMode: "async", InputSchema: model.WorkflowInputSchemaSpec{Required: []string{"policy"}, AdditionalProperties: &no, Properties: map[string]model.IntegrationSchemaProperty{"policy": {Type: "object"}}}, Steps: steps}
			switch name {
			case "operation":
				spec.Steps[1].Use.Operation = "capacity.execute_bound"
			case "for_each":
				spec.Steps[1].ForEach = &model.WorkflowForEachSpec{Items: "{{ inputs.slots }}", As: "slot"}
			case "retry":
				spec.Steps[1].Retry.MaxAttempts = 2
			case "timeout":
				spec.Steps[1].TimeoutSeconds = 601
			case "condition":
				spec.Steps[1].Condition = "true"
			case "caller_assessment":
				spec.InputSchema.Properties["assessment"] = model.IntegrationSchemaProperty{Type: "object"}
			case "caller_lease":
				spec.Steps[1].With["lease_owner"] = "{{ inputs.lease_owner }}"
			case "disabled":
				spec.Trigger.Enabled = &no
			case "actorless":
				spec.Authorization = nil
			case "hidden_step":
				spec.Steps = append(spec.Steps, spec.Steps[0])
			case "missing_phase":
				spec.Steps = spec.Steps[:6]
			case "changed_scope":
				spec.Steps[0].With["policy"] = map[string]any{"namespace": "other", "name": policy.Metadata.Name}
			}
			if (ValidateOriginalGuestReconcileGraph(spec, policy, p) == nil) != (name == "valid") {
				t.Fatal("caller/graph authority accepted", name)
			}
		})
	}
}

func TestOriginalGuestReconcileSnapshotUsesCompleteNativePartition(t *testing.T) {
	for _, name := range []string{"empty", "present", "reordered", "incomplete", "stale", "unknown", "business", "scope", "partition", "foreign_owner"} {
		t.Run(name, func(t *testing.T) {
			policy, p, inv, now := guestReconcileUnit(t)
			b := p.MutationBindings[0]
			if name != "empty" {
				for _, slot := range []int{1, 2} {
					s := b.Slots[slot-1]
					inv.Members = append(inv.Members, model.CapacityVMFleetInventoryMember{Slot: slot, DesiredSpec: *s.DesiredSpec, RequestSHA256: s.DesiredSpecSHA256, Server: model.CapacityVMServerObservation{CapacityVMNativeTuple: model.CapacityVMNativeTuple{ID: fmt.Sprintf("i-%017x", slot), CreatedAt: now.Add(-time.Hour).Format(time.RFC3339Nano)}, Name: s.DesiredSpec.NativeName, Status: "off", PhysicalSpecVerified: true, ObservedAt: inv.ObservedAt, Labels: map[string]string{"yggdrasil.io/owner": p.Owner, "yggdrasil.io/scope": vmLabelDigest(b.ScopeChecksum), "yggdrasil.io/spec": vmLabelDigest(s.DesiredSpec.ProfileChecksum), "yggdrasil.io/profile": b.ProfileName, "yggdrasil.io/slot": fmt.Sprint(slot)}}})
				}
				inv.MissingSlots = []int{3, 4, 5, 6, 7, 8}
			}
			switch name {
			case "reordered":
				inv.Members[0], inv.Members[1] = inv.Members[1], inv.Members[0]
			case "incomplete":
				inv.Complete = false
			case "stale":
				inv.ObservedAt = now.Add(-2 * time.Minute).Format(time.RFC3339Nano)
			case "unknown":
				inv.Members[0].Unresolved = true
			case "business":
				inv.BusinessReadyEvidence = true
			case "scope":
				inv.ScopeChecksum = strings.Repeat("f", 64)
			case "partition":
				inv.MissingSlots = nil
			case "foreign_owner":
				inv.Members[0].Server.Labels["yggdrasil.io/owner"] = "other"
			}
			snapshot, err := GuestReconcileSnapshot(policy, p, inv, now)
			valid := name == "empty" || name == "present" || name == "reordered"
			if (err == nil) != valid {
				t.Fatal("native source changed", name, err)
			}
			if valid && (snapshot.Units != len(inv.Members) || !strings.HasPrefix(snapshot.ResourceUID, "original-vm-profile:") || snapshot.Owner != p.Owner) {
				t.Fatal("native count/identity changed")
			}
		})
	}
}

func TestOriginalGuestReconcileDoesNotChangeProfileApprovalProjection(t *testing.T) {
	p, b, _, _ := guestProductionRegistryFixture(t)
	beforeProfile, beforeContract := GuestRetirementSHA(b.ProfileManifest), GuestProductionProfileContractSHA256(p, b, "fixture")
	p.GuestNotifyReconcileBinding = &model.CapacityGuestNotifyReconcileBinding{Mode: GuestNotifyReconcileMode}
	if GuestRetirementSHA(b.ProfileManifest) != beforeProfile || GuestProductionProfileContractSHA256(p, b, "fixture") != beforeContract {
		t.Fatal("outer binding entered original profile contract")
	}
	legacy := model.CapacityPolicySpec{}
	raw, _ := json.Marshal(legacy)
	if strings.Contains(string(raw), "guest_notify_reconcile_binding") {
		t.Fatal("legacy wire gained an optional field")
	}
}
