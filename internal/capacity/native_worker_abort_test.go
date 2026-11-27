package capacity

import (
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

func abortObservationFixture() (model.CapacityPolicySpec, model.CapacityNativeWorkerAttempt, model.CapacityNativeWorkerAbortObservation, time.Time) {
	now := time.Now().UTC()
	registry := model.CapacityNativePoolRegistryRef{Kind: "Lease", Namespace: "workers", Name: "pool", UID: uuid.NewString()}
	physical := model.CapacityNativeWorkerPhysical{ResourceID: "i-0123456789abcdef0", ProviderID: "aws:///us-east-1a/i-0123456789abcdef0", AccountID: "123456789012", InstanceType: "c7a.xlarge", NetworkID: "vpc-0123456789abcdef0", CreatedAt: now.Add(-time.Minute), ImageID: "ami-0123456789abcdef0", Region: "us-east-1", Zone: "us-east-1a", NativeIPv4: "10.90.0.2", MACAddress: "02:00:00:00:00:02", PhysicalSpecSHA256: strings.Repeat("a", 64), PhysicalBindingSHA256: strings.Repeat("b", 64), LaunchSHA256: strings.Repeat("c", 64)}
	p := model.CapacityPolicySpec{NativeWorkerPoolBinding: &model.CapacityNativeWorkerPoolBinding{RealmUID: uuid.NewString(), PoolUID: uuid.NewString(), Owner: "controller", ExpectedPoolEpoch: 3, RegistryRef: registry}, NativeWorkerLifecycleBinding: &model.CapacityNativeWorkerLifecycleBinding{MaxReadAgeSeconds: 30, PreAdmissionAbort: &model.CapacityNativeWorkerAbortBinding{Mode: model.CapacityNativeWorkerAbortSchema, Workflow: model.ManifestSelector{Namespace: "workers", Name: "cleanup"}, MaxPermitSeconds: 60}}}
	a := model.CapacityNativeWorkerAttempt{ID: uuid.New(), PoolUID: p.NativeWorkerPoolBinding.PoolUID, PoolEpoch: 3, Registry: registry, ProviderIDPrefix: "aws:///", Region: "us-east-1", PhysicalSpecSHA256: physical.PhysicalSpecSHA256, LaunchSHA256: physical.LaunchSHA256, Physical: &physical, BirthSHA256: strings.Repeat("d", 64), CreatedAt: physical.CreatedAt, Execution: model.CapacityNativeWorkerExecutionProfile{ScopeSHA256: strings.Repeat("e", 64)}}
	o := model.CapacityNativeWorkerAbortObservation{ObservedAt: now, RealmUID: p.NativeWorkerPoolBinding.RealmUID, PoolUID: a.PoolUID, Owner: "controller", Epoch: 3, Registry: registry, RegistryResourceVersion: "10", ExecutionScopeSHA256: a.Execution.ScopeSHA256, Physical: physical, ProviderOutcome: "present", ProviderEvidenceSHA256: strings.Repeat("1", 64), NodeState: "none_confirmed", NodesComplete: true, PodsComplete: true, NodeEvidenceSHA256: strings.Repeat("2", 64)}
	return p, a, o, now
}

func TestNativeWorkerAbortNeverTurnsUnknownOrUnhealthyIntoEmpty(t *testing.T) {
	p, a, o, now := abortObservationFixture()
	if !NativeWorkerAbortObservationValid(p, a, o, now) || !NativeWorkerAbortSendSafe(o) {
		t.Fatal("complete independently empty Node inventory refused")
	}
	for _, state := range []string{"unknown", "ambiguous"} {
		unknown := o
		unknown.NodeState = state
		unknown.NodesComplete = false
		unknown.PodsComplete = false
		if !NativeWorkerAbortObservationValid(p, a, unknown, now) || NativeWorkerAbortSendSafe(unknown) || NativeWorkerAbortSettled(unknown) {
			t.Fatal("uncertainty lost or converted into deletion authority", state)
		}
	}
	quarantined := o
	quarantined.NodeState = "quarantined"
	quarantined.NodeUID = uuid.NewString()
	quarantined.NodeProviderID = a.Physical.ProviderID
	quarantined.NodeResourceVersion = "12"
	quarantined.QuarantinePresent = true
	quarantined.Unschedulable = true
	if !NativeWorkerAbortObservationValid(p, a, quarantined, now) || !NativeWorkerAbortSendSafe(quarantined) {
		t.Fatal("exact cordoned empty quarantined worker refused")
	}
	for _, mutate := range []func(*model.CapacityNativeWorkerAbortObservation){
		func(v *model.CapacityNativeWorkerAbortObservation) { v.QuarantinePresent = false },
		func(v *model.CapacityNativeWorkerAbortObservation) { v.Unschedulable = false },
		func(v *model.CapacityNativeWorkerAbortObservation) { v.ApplicationPods = 1 },
		func(v *model.CapacityNativeWorkerAbortObservation) { v.PodsComplete = false },
		func(v *model.CapacityNativeWorkerAbortObservation) { v.NodesComplete = false },
		func(v *model.CapacityNativeWorkerAbortObservation) { v.NodeState = "admitted" },
	} {
		changed := quarantined
		mutate(&changed)
		if NativeWorkerAbortSendSafe(changed) {
			t.Fatal("missing pre-admission safety became destructive authority")
		}
	}
}

func TestNativeWorkerAbortScopeEpochBirthAndFreshnessAreIndependent(t *testing.T) {
	p, a, o, now := abortObservationFixture()
	for _, mutate := range []func(*model.CapacityNativeWorkerAbortObservation){
		func(v *model.CapacityNativeWorkerAbortObservation) {
			v.Physical.ProviderID = "aws:///wrong-zone/" + a.Physical.ResourceID
		},
		func(v *model.CapacityNativeWorkerAbortObservation) { v.Physical.AccountID = "999999999999" },
		func(v *model.CapacityNativeWorkerAbortObservation) {
			v.Physical.CreatedAt = v.Physical.CreatedAt.Add(time.Second)
		},
		func(v *model.CapacityNativeWorkerAbortObservation) { v.Epoch++ },
		func(v *model.CapacityNativeWorkerAbortObservation) { v.Registry.UID = uuid.NewString() },
		func(v *model.CapacityNativeWorkerAbortObservation) { v.RegistryResourceVersion = "" },
		func(v *model.CapacityNativeWorkerAbortObservation) { v.Owner = "other" },
		func(v *model.CapacityNativeWorkerAbortObservation) { v.ExecutionScopeSHA256 = strings.Repeat("f", 64) },
		func(v *model.CapacityNativeWorkerAbortObservation) { v.ObservedAt = now.Add(-31 * time.Second) },
		func(v *model.CapacityNativeWorkerAbortObservation) { v.ObservedAt = now.Add(time.Second) },
		func(v *model.CapacityNativeWorkerAbortObservation) {
			v.NodeState = "none_confirmed"
			v.NodesComplete = false
		},
	} {
		changed := o
		mutate(&changed)
		if NativeWorkerAbortObservationValid(p, a, changed, now) {
			t.Fatal("substituted or stale independent identity accepted")
		}
	}
	p.NativeWorkerPoolBinding.ProtectedNodes = []model.CapacityNativeProtectedNode{{NodeUID: uuid.NewString(), ProviderID: a.Physical.ProviderID}}
	if NativeWorkerAbortObservationValid(p, a, o, now) {
		t.Fatal("protected floor accepted as a failed worker")
	}
}

func TestNativeWorkerAbortSettlementRequiresEveryBillingAndNetworkClosure(t *testing.T) {
	_, _, o, _ := abortObservationFixture()
	o.ProviderOutcome = "not_found"
	o.RegistryEntryAbsent = true
	o.RegistryEvidenceSHA256 = strings.Repeat("3", 64)
	o.NetworkPeerAbsent = true
	o.IPAMEntryAbsent = true
	o.NetworkEvidenceSHA256 = strings.Repeat("4", 64)
	o.AncillaryChargesClosed = true
	o.ChargeEvidenceSHA256 = strings.Repeat("5", 64)
	if !NativeWorkerAbortSettled(o) {
		t.Fatal("complete typed independent closure refused")
	}
	for _, outcome := range []string{"unknown", "present", "stopped", "HTTP403", "HTTP200-empty", "timeout"} {
		changed := o
		changed.ProviderOutcome = outcome
		if NativeWorkerAbortSettled(changed) {
			t.Fatal("nonabsence released resources", outcome)
		}
	}
	for _, mutate := range []func(*model.CapacityNativeWorkerAbortObservation){
		func(v *model.CapacityNativeWorkerAbortObservation) { v.RegistryEntryAbsent = false },
		func(v *model.CapacityNativeWorkerAbortObservation) { v.NetworkPeerAbsent = false },
		func(v *model.CapacityNativeWorkerAbortObservation) { v.IPAMEntryAbsent = false },
		func(v *model.CapacityNativeWorkerAbortObservation) { v.AncillaryChargesClosed = false },
		func(v *model.CapacityNativeWorkerAbortObservation) { v.ChargeEvidenceSHA256 = "" },
		func(v *model.CapacityNativeWorkerAbortObservation) { v.NodeState = "unknown" },
		func(v *model.CapacityNativeWorkerAbortObservation) { v.ApplicationPods = 1 },
	} {
		changed := o
		mutate(&changed)
		if NativeWorkerAbortSettled(changed) {
			t.Fatal("partial worker/storage/IP/Node closure released reservation")
		}
	}
}

func TestNativeWorkerAbortBindingRemainsExplicitAndSourceSelected(t *testing.T) {
	if ValidateNativeWorkerAbortBinding(model.CapacityPolicySpec{}) != nil {
		t.Fatal("legacy policy changed")
	}
	p, _, _, _ := abortObservationFixture()
	if ValidateNativeWorkerAbortBinding(p) != nil {
		t.Fatal("explicit bounded source workflow refused")
	}
	version := 1
	for _, mutate := range []func(*model.CapacityNativeWorkerAbortBinding){
		func(v *model.CapacityNativeWorkerAbortBinding) { v.Mode = "" },
		func(v *model.CapacityNativeWorkerAbortBinding) { v.MaxPermitSeconds = 0 },
		func(v *model.CapacityNativeWorkerAbortBinding) { v.MaxPermitSeconds = 301 },
		func(v *model.CapacityNativeWorkerAbortBinding) { v.Workflow.ManifestID = uuid.NewString() },
		func(v *model.CapacityNativeWorkerAbortBinding) { v.Workflow.Version = &version },
		func(v *model.CapacityNativeWorkerAbortBinding) { v.Workflow.Namespace = "" },
	} {
		changed := *p.NativeWorkerLifecycleBinding.PreAdmissionAbort
		mutate(&changed)
		copy := p
		binding := *p.NativeWorkerLifecycleBinding
		binding.PreAdmissionAbort = &changed
		copy.NativeWorkerLifecycleBinding = &binding
		if ValidateNativeWorkerAbortBinding(copy) == nil {
			t.Fatal("implicit or caller-selected cleanup accepted")
		}
	}
}
