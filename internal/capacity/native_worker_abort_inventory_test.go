package capacity

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func nativeAbortInventoryFixture(t *testing.T) (phaseReaderFixture, model.CapacityNativeWorkerAbortInventoryObservation, time.Time) {
	t.Helper()
	now := time.Now().UTC()
	f := newPhaseReaderFixture(t, now)
	b := *f.p.NativeWorkerLifecycleBinding.PhaseObserver
	b.Name, b.ScopeSHA256, b.Adapter.ManifestID = "abort-read", marketTestSHA("8"), marketTestUUID(903)
	f.p.NativeWorkerLifecycleBinding.AbortInventoryObserver = &b
	f.p.NativeWorkerLifecycleBinding.PreAdmissionAbort = &model.CapacityNativeWorkerAbortBinding{Mode: model.CapacityNativeWorkerAbortSchema, Workflow: model.ManifestSelector{Namespace: "global", Name: "recover-workers"}, MaxPermitSeconds: 30}
	f.o.Adapter, f.o.BindingName, f.o.BindingScopeSHA256 = b.Adapter, b.Name, b.ScopeSHA256
	name, err := NativeWorkerBootstrapNodeName(f.a)
	if err != nil {
		t.Fatal(err)
	}
	f.o.Candidates[0].NodeName = name
	in := model.CapacityNativeWorkerAbortInventoryObservation{Schema: "native_worker_abort_inventory_v1", SourceCommit: b.SourceCommit, BindingScopeSHA256: b.ScopeSHA256, Adapter: b.Adapter, BindingName: b.Name, Requested: model.CapacityNativeWorkerAbortInventoryRequest{BindingName: b.Name, ProviderID: f.a.Physical.ProviderID, CreationProofSHA256: f.a.BirthSHA256, NodeName: name}, ObservedAt: now, Phase: f.o, BeforePhaseEvidence: marketTestSHA("1"), Complete: true, PodsComplete: true, PodsAllNamespaces: true, PodCollectionVersion: "original-all-namespace-pods-rv", TargetPodEvidenceSHA256: marketTestSHA("2"), EvidenceSHA256: marketTestSHA("3")}
	return f, in, now
}

func TestNativeAbortInventoryCannotReplaceCompletePodsWithMissingOrUnhealthyNode(t *testing.T) {
	f, in, now := nativeAbortInventoryFixture(t)
	base := model.CapacityNativeWorkerAbortObservation{ProviderOutcome: "present", ProviderEvidenceSHA256: marketTestSHA("4")}
	// This Node is quarantined but still schedulable. No unsafe deletion grant.
	o, err := NativeWorkerApplyAbortInventory(f.p, f.a, in, base, now)
	if err != nil || o.NodeState != "quarantined" || NativeWorkerAbortSendSafe(o) {
		t.Fatal("schedulable Node authorized deletion", err)
	}
	in.Phase.Candidates[0].Unschedulable = true
	o, err = NativeWorkerApplyAbortInventory(f.p, f.a, in, base, now)
	if err != nil || !NativeWorkerAbortSendSafe(o) {
		t.Fatal("exact cordoned/quarantined empty Node refused", err)
	}
	in.TargetActivePods = 1
	o, err = NativeWorkerApplyAbortInventory(f.p, f.a, in, base, now)
	if err != nil || NativeWorkerAbortSendSafe(o) {
		t.Fatal("infrastructure or deleting Pod was exempted", err)
	}
	in.TargetActivePods = 0
	in.Phase.Candidates = []model.CapacityNativeWorkerPhaseCandidate{}
	in.Phase.CandidateAbsenceProven = true
	o, err = NativeWorkerApplyAbortInventory(f.p, f.a, in, base, now)
	if err != nil || o.NodeState != "none_confirmed" || !NativeWorkerAbortSendSafe(o) || !o.RegistryEntryAbsent {
		t.Fatal("complete original-name absence refused", err)
	}
	in.PodsComplete = false
	if _, err = NativeWorkerApplyAbortInventory(f.p, f.a, in, base, now); err == nil {
		t.Fatal("absent Node erased incomplete Pod inventory")
	}
}

func TestNativeAbortInventoryRejectsScopeBirthNodeAndCollectionDrift(t *testing.T) {
	f, in, now := nativeAbortInventoryFixture(t)
	for _, fault := range []string{"source", "scope", "old_phase_scope", "adapter", "selector", "hostname", "birth", "realm", "epoch", "registry", "pod_snapshot", "partial", "authority", "future", "stale", "uid", "provider", "policy_label", "lost_quarantine"} {
		t.Run(fault, func(t *testing.T) {
			raw, _ := json.Marshal(in)
			var bad model.CapacityNativeWorkerAbortInventoryObservation
			_ = json.Unmarshal(raw, &bad)
			switch fault {
			case "source":
				bad.SourceCommit = marketTestSHA("a")
			case "scope":
				bad.BindingScopeSHA256 = marketTestSHA("0")
			case "old_phase_scope":
				bad.Phase.BindingScopeSHA256 = f.p.NativeWorkerLifecycleBinding.PhaseObserver.ScopeSHA256
			case "adapter":
				bad.Adapter.Version++
			case "selector":
				bad.Requested.ProviderID = "hcloud://other"
			case "hostname":
				bad.Phase.Candidates[0].NodeName = "different-node"
			case "birth":
				bad.Phase.RequestedCreationProofSHA256 = marketTestSHA("0")
			case "realm":
				bad.Phase.Registry.RealmUID = marketTestUUID(904)
			case "epoch":
				bad.Phase.Registry.Epoch++
			case "registry":
				bad.Phase.Registry.Ref.UID = marketTestUUID(905)
			case "pod_snapshot":
				bad.PodCollectionVersion = ""
			case "partial":
				bad.Phase.FullCollectionComplete = false
			case "authority":
				bad.MutationAuthorized = true
			case "future":
				bad.ObservedAt = now.Add(time.Second)
			case "stale":
				bad.ObservedAt = now.Add(-time.Hour)
			case "uid":
				bad.Phase.Candidates[0].NodeUID = "unknown"
			case "provider":
				bad.Phase.Candidates[0].ProviderID = "hcloud://other"
			case "policy_label":
				bad.Phase.Candidates[0].PolicyIDLabel = marketTestUUID(906)
			case "lost_quarantine":
				bad.Phase.Candidates[0].Taints = nil
			}
			o, err := NativeWorkerApplyAbortInventory(f.p, f.a, bad, model.CapacityNativeWorkerAbortObservation{ProviderOutcome: "present", ProviderEvidenceSHA256: marketTestSHA("4")}, now)
			if fault == "lost_quarantine" {
				if err != nil || o.NodeState != "admitted" || NativeWorkerAbortSendSafe(o) {
					t.Fatal("lost quarantine authorized abort", err)
				}
				return
			}
			if err == nil {
				t.Fatal("changed original or partial read qualified", fault)
			}
		})
	}
}

func TestNativeAbortInventoryKeepsRegisteredOrAdmittedIdentityAfterNodeAbsence(t *testing.T) {
	f, in, now := nativeAbortInventoryFixture(t)
	f.registered(false)
	in.Phase = f.o
	base := model.CapacityNativeWorkerAbortObservation{}
	o, err := NativeWorkerApplyAbortInventory(f.p, f.a, in, base, now)
	if err != nil || o.RegistryEntryAbsent {
		t.Fatal("registered Node was omitted from registry custody", err)
	}
	f.registered(true)
	in.Phase = f.o
	o, err = NativeWorkerApplyAbortInventory(f.p, f.a, in, base, now)
	if err != nil || o.NodeState != "admitted" {
		t.Fatal("admitted registry did not fence pre-admission cleanup", err)
	}
	in.Phase.Candidates = []model.CapacityNativeWorkerPhaseCandidate{}
	in.Phase.CandidateAbsenceProven = true
	if _, err = NativeWorkerApplyAbortInventory(f.p, f.a, in, base, now); err == nil {
		t.Fatal("absent Node erased retained admission")
	}
}
