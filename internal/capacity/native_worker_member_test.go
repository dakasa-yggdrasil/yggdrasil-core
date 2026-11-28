package capacity

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// The existing generic hcloud fixture deliberately makes no claim to the
// literal hetzner provider or its separately required HCloud witness.
type memberFactsFixture struct {
	Policy    model.CapacityPolicySpec
	Attempt   model.CapacityNativeWorkerAttempt
	Context   model.CapacityNativeWorkerMemberContext
	Read      model.CapacityNativeWorkerMemberObservation
	Authority NativeWorkerMemberAuthority
	Bootstrap model.CapacityNativeWorkerPlacementBootstrapObservation
	Now       time.Time
}

func newMemberFactsFixture(t *testing.T, admitted bool) memberFactsFixture {
	t.Helper()
	now := time.Date(2026, 11, 28, 12, 0, 0, 0, time.UTC)
	f := newPhaseReaderFixture(t, now)
	f.p = nativeWorkerNetworkPolicy(t)
	life, pool := f.p.NativeWorkerLifecycleBinding, f.p.NativeWorkerPoolBinding
	life.PreAdmissionAbort = &model.CapacityNativeWorkerAbortBinding{Mode: model.CapacityNativeWorkerAbortSchema, Workflow: model.ManifestSelector{Namespace: "global", Name: "recover-workers"}, MaxPermitSeconds: 30}
	for i := range life.Profiles {
		life.Profiles[i].GuestIdentityPolicySHA256 = marketTestSHA("3")
	}
	endpoint := func(id int, name, scope string) model.CapacityNativeWorkerProbeResourceBinding {
		a := marketTestAdapter()
		a.ManifestID = marketTestUUID(id)
		return model.CapacityNativeWorkerProbeResourceBinding{Adapter: a, Name: name, SourceCommit: strings.Repeat("f", 40), ScopeSHA256: marketTestSHA(scope)}
	}
	life.Members = &model.CapacityNativeWorkerMemberBinding{Mode: NativeWorkerMemberMode, Name: "owned-members", Writer: endpoint(930, "member-write", "a"), Reader: endpoint(931, "member-read", "b"), AllocatorFenceReader: endpoint(932, "allocator-read", "c"), BootstrapPolicySHA256: marketTestSHA("d"), MaxPermitSeconds: 30, MaxReadAgeSeconds: 30}
	life.Members.Writer.PrincipalID = "member-writer/fixed"
	f.a.Execution = life.Profiles[0]
	f.a.OverlayIPv4 = "10.90.0.7"
	f.o.Candidates[0].Addresses[0].Address = f.a.OverlayIPv4
	name, err := NativeWorkerBootstrapNodeName(f.a)
	if err != nil {
		t.Fatal(err)
	}
	f.o.Candidates[0].NodeName = name
	f.registered(admitted)
	if admitted {
		f.a.State = "admitted"
		f.o.Candidates[0].Taints = nil
	}
	n := &f.o.Candidates[0]
	// The inherited phase fixture is intentionally below the pool's useful
	// memory floor. This member fixture explicitly supplies a useful candidate;
	// the production readiness thresholds remain unchanged.
	n.AllocatableMilliCPU = pool.Profiles[0].MinAllocatableMilliCPU
	n.AllocatableMemoryBytes = pool.Profiles[0].MinAllocatableMemory
	n.Taints = append(n.Taints, model.CapacityNativeWorkerPhaseTaint{Key: NativeWorkerReservedTaint, Value: pool.PoolUID, Effect: "NoSchedule"})
	n.ProfileLabel, n.PhysicalSpecSHA256Label = f.a.Profile, f.a.PhysicalSpecSHA256
	n.CreationProofSHA256Label, n.PolicyIDLabel = f.a.BirthSHA256, f.a.PolicyID.String()
	reader := life.Members.Reader
	f.o.SourceCommit, f.o.Adapter = reader.SourceCommit, reader.Adapter
	f.o.BindingName, f.o.BindingScopeSHA256 = reader.Name, reader.ScopeSHA256
	// The member reader derives its realm namespace from the pool registry;
	// the legacy phase reader's separate "realm" scope is not its counterpart.
	f.o.Registry.RealmNamespace = pool.RegistryRef.Namespace
	mode, receipt := "never_admitted", ""
	if admitted {
		mode, receipt = "admitted", f.o.Registrations[0].Admission.ReceiptSHA256
	}
	c := model.CapacityNativeWorkerMemberContext{Schema: model.CapacityNativeWorkerMemberContextSchema, PlanID: marketTestUUID(940), PermitID: marketTestUUID(941), AttemptID: f.a.ID.String(), CoreSourceCommit: f.a.SourceCommit, Mode: mode, Action: "cordon", Actor: NativeWorkerMemberEndpoint(life.Members.Writer, "ensure_native_worker_pool_member"), Observer: NativeWorkerMemberEndpoint(reader, "observe_native_worker_pool_member"), PolicyID: f.a.PolicyID.String(), PolicyChecksum: f.a.PolicyChecksum, IntentGeneration: f.a.Generation, FencingToken: f.a.FencingToken, RealmNamespace: pool.RegistryRef.Namespace, RealmUID: pool.RealmUID, PoolUID: pool.PoolUID, Owner: pool.Owner, Epoch: pool.ExpectedPoolEpoch, Profile: f.a.Profile, BirthSHA256: f.a.BirthSHA256, Physical: *f.a.Physical, OverlayIPv4: f.a.OverlayIPv4, Node: &model.CapacityNativeWorkerMemberNode{Name: name, UID: n.NodeUID, ResourceVersion: n.NodeResourceVersion, ProviderID: n.ProviderID}, Registry: f.a.Registry, RegistryResourceVersion: f.o.Registry.ResourceVersion, RegistrySHA256: f.o.Registry.AnnotationSHA256, PlacementFenceSHA256: marketTestSHA("e"), BootstrapPolicySHA256: life.Members.BootstrapPolicySHA256, AdmissionReceiptSHA256: receipt, NotAfter: now.Add(25 * time.Second)}
	in := model.CapacityNativeWorkerAbortInventoryObservation{Schema: "native_worker_abort_inventory_v1", SourceCommit: reader.SourceCommit, BindingScopeSHA256: reader.ScopeSHA256, Adapter: reader.Adapter, BindingName: reader.Name, Requested: model.CapacityNativeWorkerAbortInventoryRequest{BindingName: reader.Name, ProviderID: c.Physical.ProviderID, CreationProofSHA256: c.BirthSHA256, NodeName: name}, ObservedAt: now, Phase: f.o, BeforePhaseEvidence: marketTestSHA("1"), Complete: true, PodsComplete: true, PodsAllNamespaces: true, PodCollectionVersion: "all-namespace-pods-rv", TargetPodEvidenceSHA256: marketTestSHA("2"), EvidenceSHA256: marketTestSHA("3")}
	o := model.CapacityNativeWorkerMemberObservation{Schema: model.CapacityNativeWorkerMemberObservationSchema, BindingName: reader.Name, PermitID: c.PermitID, SourceCommit: reader.SourceCommit, ScopeSHA256: reader.ScopeSHA256, Adapter: reader.Adapter, ContextSHA256: NativeWorkerMemberContextSHA(c), ReadID: marketTestUUID(942), ObservedAt: now, Inventory: in, Pods: []model.CapacityNativeWorkerMemberPodFact{}, ControllerReadsComplete: true, PDBReadsComplete: true, StorageReadsComplete: true, Complete: true}
	o.Configuration = &model.CapacityNativeWorkerKubeConfigurationObservation{Schema: model.CapacityNativeWorkerKubeConfigurationSchema, NodeName: name, NodeUID: n.NodeUID, NodeResourceVersion: n.NodeResourceVersion, KubeletVersion: "v1.34.6+k3s1", EndpointIPv4: c.OverlayIPv4, ServerLeafSHA256: marketTestSHA("4"), ObservedAt: now, HTTPStatus: 200, ConfigurationPresent: true, ReadComplete: true, PrivateOriginalRef: o.ReadID}
	controller := model.CapacityNativeWorkerMemberController{APIVersion: "apps/v1", Kind: "ReplicaSet", Namespace: "business", Name: "nw-worker-rs", UID: marketTestUUID(943), ResourceVersion: "81", Generation: 2, ObservedGeneration: 2}
	deployment := model.CapacityNativeWorkerMemberController{APIVersion: "apps/v1", Kind: "Deployment", Namespace: "business", Name: "nw-worker", UID: marketTestUUID(944), ResourceVersion: "82", Generation: 2, ObservedGeneration: 2}
	authority := NativeWorkerMemberAuthority{WorkloadContracts: []string{"business/worker"}, WorkloadLineage: map[string][]model.CapacityNativeWorkerMemberController{"business/worker": {controller, deployment}}, SystemSourceCommit: f.a.Execution.BootstrapSourceCommit, KubeletVersion: "v1.34.6+k3s1", AgentConfigPath: "/etc/rancher/k3s/config.yaml", ConfiguredKubeletArgs: []string{"pod-manifest-path=", "manifest-url=", "cloud-provider="}}
	boot := model.CapacityNativeWorkerPlacementBootstrapObservation{Schema: model.CapacityNativeWorkerPlacementBootstrapSchema, SourceCommit: authority.SystemSourceCommit, AttemptID: f.a.ID.String(), LaunchSHA256: f.a.LaunchSHA256, ProviderID: c.Physical.ProviderID, NodeName: name, ObservedAt: now, AgentPID: 123, AgentStartTicks: 456, ActualAgentArgv: []string{"/usr/local/bin/k3s", "agent", "--config", authority.AgentConfigPath}, AgentConfigPath: authority.AgentConfigPath, ConfiguredKubeletArgs: append([]string(nil), authority.ConfiguredKubeletArgs...), ConfiguredNodeIPv4: c.OverlayIPv4, AgentConfigComplete: true}
	out := memberFactsFixture{f.p, f.a, c, o, authority, boot, now}
	out.reseal()
	if err = ValidateNativeWorkerLifecycleBinding(out.Policy); err != nil {
		t.Fatal("member fixture policy is not coherent", err)
	}
	out.requireValid(t)
	return out
}

func (f *memberFactsFixture) reseal() {
	f.Read.ContextSHA256 = NativeWorkerMemberContextSHA(f.Context)
	f.Read.PodRosterSHA256 = NativeWorkerMemberPodRosterSHA(f.Read.Pods)
}

func (f memberFactsFixture) requireValid(t *testing.T) {
	t.Helper()
	if err := NativeWorkerMemberContextValid(f.Policy, f.Attempt, f.Context, f.Now, false); err != nil {
		t.Fatal("coherent independent member context refused", err)
	}
	if err := NativeWorkerPhaseHeaderValid(nativeMemberPhasePolicy(f.Policy), f.Read.Inventory.Phase, f.Now); err != nil {
		t.Fatal("coherent independent member phase header refused", err)
	}
	if err := NativeWorkerMemberObservationValid(f.Policy, f.Attempt, f.Context, f.Read, f.Authority, f.Now, false); err != nil {
		t.Fatal("coherent independent member fixture refused", err)
	}
	if !NativeWorkerPlacementBootstrapValid(f.Policy, f.Attempt, f.Context, f.Bootstrap, f.Authority, f.Now) {
		t.Fatal("coherent bootstrap fixture refused")
	}
}

func (f memberFactsFixture) copy(t *testing.T) memberFactsFixture {
	t.Helper()
	raw, err := json.Marshal(f)
	var out memberFactsFixture
	if err != nil || json.Unmarshal(raw, &out) != nil {
		t.Fatal("copy public member fixture")
	}
	return out
}

func (f memberFactsFixture) pod(name string, id int) model.CapacityNativeWorkerMemberPodFact {
	return model.CapacityNativeWorkerMemberPodFact{Identity: model.CapacityNativeWorkerMemberPod{Namespace: "business", Name: "nw-" + name, UID: marketTestUUID(id), ResourceVersion: "pod-rv-1"}, NodeName: f.Context.Node.Name, Phase: "Running", TerminationGraceSeconds: 30, Finalizers: []string{}, Controllers: append([]model.CapacityNativeWorkerMemberController(nil), f.Authority.WorkloadLineage["business/worker"]...), PDBs: []model.CapacityNativeWorkerMemberPDB{}, ContractID: "business/worker", ContractMatched: true, StorageKinds: []string{"secret"}}
}

func newMemberBindFixture(t *testing.T) memberFactsFixture {
	t.Helper()
	f := newMemberFactsFixture(t, true)
	pod := f.pod("pending-worker", 950)
	pod.NodeName, pod.Phase = "", "Pending"
	f.Context.Action = "bind_pod"
	f.Context.Actor.Capability = "ensure_native_worker_pod_placement"
	f.Context.Observer.Capability = "observe_native_worker_pod_placement"
	target := pod.Identity
	f.Context.Pod = &target
	f.Read.SubjectPod = &pod
	f.reseal()
	f.requireValid(t)
	return f
}

func TestNativeWorkerMemberBindingsSeparatePrincipalsAndClosedActions(t *testing.T) {
	f := newMemberFactsFixture(t, false)
	legacy := f.copy(t)
	legacy.Policy.NativeWorkerLifecycleBinding.Members = nil
	if ValidateNativeWorkerMemberBinding(legacy.Policy) != nil {
		t.Fatal("absent optional member declaration changed legacy validation")
	}
	if NativeWorkerMemberContextValid(legacy.Policy, legacy.Attempt, legacy.Context, legacy.Now, false) == nil {
		t.Fatal("absent binding authorized a context")
	}
	for _, fault := range []string{"reader_principal", "writer_missing_principal", "shared_actor", "shared_scope", "provider_actor", "missing_guest_identity", "missing_network", "duration"} {
		t.Run(fault, func(t *testing.T) {
			bad := f.copy(t)
			l := bad.Policy.NativeWorkerLifecycleBinding
			switch fault {
			case "reader_principal":
				l.Members.Reader.PrincipalID = "borrowed-writer"
			case "writer_missing_principal":
				l.Members.Writer.PrincipalID = ""
			case "shared_actor":
				l.Members.Reader.Adapter = l.Members.Writer.Adapter
			case "shared_scope":
				l.Members.AllocatorFenceReader.ScopeSHA256 = l.Members.Reader.ScopeSHA256
			case "provider_actor":
				l.Members.Writer.Adapter = l.Profiles[0].Adapter
			case "missing_guest_identity":
				l.Profiles[0].GuestIdentityPolicySHA256 = ""
			case "missing_network":
				l.Network = nil
			case "duration":
				l.Members.MaxPermitSeconds = 31
			}
			if ValidateNativeWorkerMemberBinding(bad.Policy) == nil {
				t.Fatal("unqualified member binding accepted")
			}
		})
	}
	for _, pair := range [][2]string{{"cordon", "placement"}, {"bind_pod", "retirement"}, {"provider_destroy", "retirement"}, {"admit", "retirement"}, {"evict_pod", "unknown"}, {"CORDON", "retirement"}} {
		if NativeWorkerMemberCapability(pair[0], pair[1]) != "" {
			t.Fatal("unsupported action acquired a capability", pair)
		}
	}
	if NativeWorkerMemberCapability("evict_pod", "placement") == NativeWorkerMemberCapability("evict_pod", "retirement") {
		t.Fatal("placement eviction borrowed retirement capability")
	}
}

func TestNativeWorkerMemberPlacementSubjectAndCompletePodRoster(t *testing.T) {
	f := newMemberBindFixture(t)
	if len(f.Read.Pods) != 0 || f.Read.SubjectPod == nil || f.Read.SubjectPod.NodeName != "" {
		t.Fatal("pending SubjectPod was put in the target roster")
	}
	for _, fault := range []string{"missing_subject", "target_mismatch", "already_assigned", "subject_in_roster", "deleting", "controller_substitution", "PVC", "incomplete_storage"} {
		t.Run(fault, func(t *testing.T) {
			bad := f.copy(t)
			switch fault {
			case "missing_subject":
				bad.Read.SubjectPod = nil
			case "target_mismatch":
				bad.Read.SubjectPod.Identity.UID = marketTestUUID(999)
			case "already_assigned":
				bad.Read.SubjectPod.NodeName = bad.Context.Node.Name
			case "subject_in_roster":
				p := *bad.Read.SubjectPod
				p.NodeName = bad.Context.Node.Name
				bad.Read.Pods = append(bad.Read.Pods, p)
				bad.Read.Inventory.TargetActivePods = 1
			case "deleting":
				bad.Read.SubjectPod.Deleting = true
			case "controller_substitution":
				bad.Read.SubjectPod.Controllers[0].UID = marketTestUUID(999)
			case "PVC":
				bad.Read.SubjectPod.StorageKinds = []string{"persistent_volume_claim"}
			case "incomplete_storage":
				bad.Read.StorageReadsComplete = false
			}
			bad.reseal()
			if NativeWorkerMemberObservationValid(bad.Policy, bad.Attempt, bad.Context, bad.Read, bad.Authority, bad.Now, false) == nil {
				t.Fatal("unbound subject or complete-roster guard lost")
			}
		})
	}
	// Terminal and deleting Pods remain actual roster members. A Source-known
	// DaemonSet is counted too; its unsupported contract never erases a Pod.
	r := newMemberFactsFixture(t, false)
	for i, phase := range []string{"Running", "Succeeded", "Failed"} {
		p := r.pod("roster-"+strings.ToLower(phase), 960+i)
		p.Phase = phase
		r.Read.Pods = append(r.Read.Pods, p)
	}
	r.Read.Inventory.TargetActivePods = 1
	r.reseal()
	r.requireValid(t)
	ds := r.pod("deleting-daemon", 963)
	ds.Deleting, ds.ContractID = true, "system/known-daemon"
	ds.Controllers[0].Kind, ds.Controllers[0].Name = "DaemonSet", "known-daemon"
	r.Authority.WorkloadContracts = append(r.Authority.WorkloadContracts, ds.ContractID)
	r.Authority.WorkloadLineage[ds.ContractID] = append([]model.CapacityNativeWorkerMemberController(nil), ds.Controllers...)
	r.Read.Pods = append(r.Read.Pods, ds)
	r.Read.Inventory.TargetActivePods = 2
	r.reseal()
	if len(r.Read.Pods) != 4 || r.Read.Inventory.TargetActivePods != 2 || NativeWorkerMemberObservationValid(r.Policy, r.Attempt, r.Context, r.Read, r.Authority, r.Now, false) == nil {
		t.Fatal("unsupported DaemonSet was discounted or authorized")
	}
	// A preparing eviction selects the actual Pod UID/name/namespace. A later
	// GET may have a new RV; only a new final context can seal that preimage.
	evict := newMemberFactsFixture(t, false)
	pod := evict.pod("evict-worker", 964)
	evict.Context.Action, evict.Context.Actor.Capability = "evict_pod", "destroy_native_worker_pool_member"
	target := pod.Identity
	evict.Context.Pod = &target
	pod.Identity.ResourceVersion = "later-pod-rv"
	evict.Read.Pods = []model.CapacityNativeWorkerMemberPodFact{pod}
	evict.Read.Inventory.TargetActivePods = 1
	evict.reseal()
	if err := NativeWorkerMemberObservationValid(evict.Policy, evict.Attempt, evict.Context, evict.Read, evict.Authority, evict.Now, true); err != nil {
		t.Fatal("seed could not select the same Pod after an RV update", err)
	}
	if NativeWorkerMemberObservationValid(evict.Policy, evict.Attempt, evict.Context, evict.Read, evict.Authority, evict.Now, false) == nil {
		t.Fatal("seed RV relaxation leaked into the final writer preimage")
	}
	evict.Context.Pod.ResourceVersion = pod.Identity.ResourceVersion
	evict.Read.Pods[0].PDBs = []model.CapacityNativeWorkerMemberPDB{{Namespace: "business", Name: "worker-budget", UID: marketTestUUID(965), ResourceVersion: "pdb-rv", Generation: 2, ObservedGeneration: 2, DisruptionsAllowed: 1, DisruptedPods: map[string]time.Time{}}}
	evict.reseal()
	evict.requireValid(t)
	for _, fault := range []string{"no_disruption", "already_disrupted", "old_generation", "unknown_disruptions"} {
		t.Run(fault, func(t *testing.T) {
			bad := evict.copy(t)
			pdb := &bad.Read.Pods[0].PDBs[0]
			switch fault {
			case "no_disruption":
				pdb.DisruptionsAllowed = 0
			case "already_disrupted":
				pdb.DisruptedPods[bad.Context.Pod.Name] = bad.Now
			case "old_generation":
				pdb.ObservedGeneration--
			case "unknown_disruptions":
				pdb.DisruptedPods = nil
			}
			bad.reseal()
			if NativeWorkerMemberObservationValid(bad.Policy, bad.Attempt, bad.Context, bad.Read, bad.Authority, bad.Now, false) == nil {
				t.Fatal("eviction ignored current PDB disposition")
			}
		})
	}
	r.Read.Inventory.TargetActivePods = 0
	if NativeWorkerMemberObservationValid(r.Policy, r.Attempt, r.Context, r.Read, r.Authority, r.Now, false) == nil {
		t.Fatal("deleting/DaemonSet Pods disappeared from the active count")
	}
	r.Read.Pods = r.Read.Pods[1:3]
	r.Context.Action, r.Context.Actor.Capability = "delete_node", "destroy_native_worker_pool_member"
	r.Context.PhysicalAbsenceEvidenceSHA256 = marketTestSHA("5")
	r.Read.Configuration = nil
	r.Read.Inventory.Phase.Candidates[0].Unschedulable = true
	r.reseal()
	if NativeWorkerMemberObservationValid(r.Policy, r.Attempt, r.Context, r.Read, r.Authority, r.Now, false) == nil {
		t.Fatal("terminal Pods were mistaken for a zero-Pod delete preimage")
	}
}

func TestNativeWorkerMemberRejectsCoherentIdentityAndScopeSubstitution(t *testing.T) {
	for _, target := range []string{"pod", "deployment"} {
		t.Run("reserved_prefix_"+target, func(t *testing.T) {
			f := newMemberBindFixture(t)
			if target == "pod" {
				f.Context.Pod.Name = "ordinary-worker"
				f.Read.SubjectPod.Identity.Name = "ordinary-worker"
			} else {
				f.Read.SubjectPod.Controllers[1].Name = "ordinary-worker"
				f.Authority.WorkloadLineage["business/worker"][1].Name = "ordinary-worker"
			}
			f.reseal()
			if NativeWorkerMemberObservationValid(f.Policy, f.Attempt, f.Context, f.Read, f.Authority, f.Now, false) == nil {
				t.Fatal("ordinary workload entered Native placement")
			}
		})
	}

	f := newMemberFactsFixture(t, true)
	for _, fault := range []string{"core_source", "actor_source", "actor_scope", "registry", "epoch", "birth", "provider", "node_uid", "reader_source", "read_scope", "private_read_id"} {
		t.Run(fault, func(t *testing.T) {
			bad := f.copy(t)
			switch fault {
			case "core_source":
				bad.Context.CoreSourceCommit = strings.Repeat("0", 40)
			case "actor_source":
				bad.Context.Actor.SourceCommit = strings.Repeat("0", 40)
			case "actor_scope":
				bad.Context.Actor.ScopeSHA256 = marketTestSHA("0")
			case "registry":
				bad.Context.Registry.UID = marketTestUUID(999)
			case "epoch":
				bad.Context.Epoch++
			case "birth":
				bad.Context.BirthSHA256 = marketTestSHA("0")
				bad.Read.Inventory.Requested.CreationProofSHA256 = bad.Context.BirthSHA256
				bad.Read.Inventory.Phase.RequestedCreationProofSHA256 = bad.Context.BirthSHA256
				bad.Read.Inventory.Phase.Registrations[0].CreationProofSHA256 = bad.Context.BirthSHA256
				bad.Read.Inventory.Phase.Candidates[0].Registrations[0].CreationProofSHA256 = bad.Context.BirthSHA256
				bad.Read.Inventory.Phase.Candidates[0].CreationProofSHA256Label = bad.Context.BirthSHA256
			case "provider":
				bad.Context.Physical.ResourceID = "177895231"
				bad.Context.Physical.ProviderID = "hcloud://177895231"
				bad.Context.Node.ProviderID = bad.Context.Physical.ProviderID
				bad.Read.Inventory.Requested.ProviderID = bad.Context.Physical.ProviderID
				bad.Read.Inventory.Phase.RequestedProviderID = bad.Context.Physical.ProviderID
				bad.Read.Inventory.Phase.Registrations[0].ProviderID = bad.Context.Physical.ProviderID
				bad.Read.Inventory.Phase.Candidates[0].Registrations[0].ProviderID = bad.Context.Physical.ProviderID
				bad.Read.Inventory.Phase.Candidates[0].ProviderID = bad.Context.Physical.ProviderID
			case "node_uid":
				bad.Context.Node.UID = marketTestUUID(999)
			case "reader_source":
				bad.Read.SourceCommit = strings.Repeat("0", 40)
			case "read_scope":
				bad.Read.ScopeSHA256 = marketTestSHA("0")
			case "private_read_id":
				bad.Read.Configuration.PrivateOriginalRef = marketTestUUID(999)
			}
			bad.reseal()
			if err := NativeWorkerPhaseHeaderValid(nativeMemberPhasePolicy(bad.Policy), bad.Read.Inventory.Phase, bad.Now); err != nil {
				t.Fatal("negative lost its independently valid current header", err)
			}
			if NativeWorkerMemberObservationValid(bad.Policy, bad.Attempt, bad.Context, bad.Read, bad.Authority, bad.Now, false) == nil {
				t.Fatal("coherent substitution replaced the stored birth or scope")
			}
		})
	}
	// History can be read after the grant deadline; this pure function cannot
	// redeem it or turn that historical identity into a new mutation right.
	if NativeWorkerMemberContextValid(f.Policy, f.Attempt, f.Context, f.Context.NotAfter.Add(time.Minute), false) != nil {
		t.Fatal("historical identity incorrectly expired")
	}
}

func TestNativeWorkerMemberConfigurationBootstrapAndFactClocks(t *testing.T) {
	f := newMemberFactsFixture(t, false)
	for _, fault := range []string{"static_path", "static_url", "wrong_version", "malformed_leaf", "wrong_address", "incomplete", "stale", "future", "unreserved", "foreign_reservation", "duplicate_reservation", "cloud_uninitialized", "missing_quarantine"} {
		t.Run(fault, func(t *testing.T) {
			bad := f.copy(t)
			switch fault {
			case "static_path":
				bad.Read.Configuration.StaticPodPath = "/etc/kubernetes/manifests"
			case "static_url":
				bad.Read.Configuration.StaticPodURL = "https://example.invalid/manifests"
			case "wrong_version":
				bad.Read.Configuration.KubeletVersion = "v1.31.0"
			case "malformed_leaf":
				bad.Read.Configuration.ServerLeafSHA256 = "unknown"
			case "wrong_address":
				bad.Read.Configuration.EndpointIPv4 = "10.90.0.99"
			case "incomplete":
				bad.Read.Configuration.ReadComplete = false
			case "stale":
				bad.Read.Configuration.ObservedAt = bad.Now.Add(-30 * time.Second)
			case "future":
				bad.Read.Configuration.ObservedAt = bad.Now.Add(time.Second)
			case "unreserved":
				bad.Read.Inventory.Phase.Candidates[0].Taints = bad.Read.Inventory.Phase.Candidates[0].Taints[:1]
			case "foreign_reservation":
				bad.Read.Inventory.Phase.Candidates[0].Taints[1].Value = marketTestUUID(999)
			case "duplicate_reservation":
				bad.Read.Inventory.Phase.Candidates[0].Taints = append(bad.Read.Inventory.Phase.Candidates[0].Taints, bad.Read.Inventory.Phase.Candidates[0].Taints[1])
			case "cloud_uninitialized":
				bad.Read.Inventory.Phase.Candidates[0].Taints = append(bad.Read.Inventory.Phase.Candidates[0].Taints, model.CapacityNativeWorkerPhaseTaint{Key: "node.cloudprovider.kubernetes.io/uninitialized"})
			case "missing_quarantine":
				bad.Read.Inventory.Phase.Candidates[0].Taints = bad.Read.Inventory.Phase.Candidates[0].Taints[1:]
			}
			if NativeWorkerMemberObservationValid(bad.Policy, bad.Attempt, bad.Context, bad.Read, bad.Authority, bad.Now, false) == nil {
				t.Fatal("unqualified configuration or reservation accepted")
			}
		})
	}
	rotated := f.copy(t)
	rotated.Read.Configuration.ServerLeafSHA256 = marketTestSHA("5")
	rotated.requireValid(t) // CA/SAN/private capture qualify the actual leaf, not a global leaf pin.
	for _, fault := range []string{"old_guest", "future_guest", "wrong_source", "wrong_attempt", "wrong_launch", "wrong_IP", "wrong_process", "missing_ticks", "changed_args", "static_config", "incomplete_config"} {
		t.Run(fault, func(t *testing.T) {
			bad := f.copy(t)
			switch fault {
			case "old_guest":
				bad.Bootstrap.ObservedAt = bad.Now.Add(-30 * time.Second)
			case "future_guest":
				bad.Bootstrap.ObservedAt = bad.Now.Add(time.Second)
			case "wrong_source":
				bad.Bootstrap.SourceCommit = strings.Repeat("0", 40)
			case "wrong_attempt":
				bad.Bootstrap.AttemptID = marketTestUUID(999)
			case "wrong_launch":
				bad.Bootstrap.LaunchSHA256 = marketTestSHA("0")
			case "wrong_IP":
				bad.Bootstrap.ConfiguredNodeIPv4 = "10.90.0.99"
			case "wrong_process":
				bad.Bootstrap.ActualAgentArgv = []string{"/usr/local/bin/k3s", "server"}
			case "missing_ticks":
				bad.Bootstrap.AgentStartTicks = 0
			case "changed_args":
				bad.Bootstrap.ConfiguredKubeletArgs[0] = "pod-manifest-path=/etc/static"
			case "static_config":
				bad.Authority.ConfiguredKubeletArgs[0] = "pod-manifest-path=/etc/static"
				bad.Bootstrap.ConfiguredKubeletArgs[0] = bad.Authority.ConfiguredKubeletArgs[0]
			case "incomplete_config":
				bad.Bootstrap.AgentConfigComplete = false
			}
			if NativeWorkerPlacementBootstrapValid(bad.Policy, bad.Attempt, bad.Context, bad.Bootstrap, bad.Authority, bad.Now) {
				t.Fatal("unqualified guest bootstrap accepted")
			}
		})
	}
	f.Bootstrap.ActualAgentArgv = []string{"/usr/local/bin/k3s agent"}
	if !NativeWorkerPlacementBootstrapValid(f.Policy, f.Attempt, f.Context, f.Bootstrap, f.Authority, f.Now) {
		t.Fatal("actual single k3s process title refused")
	}
	facts := NativeWorkerMemberFacts{Observation: f.copy(t).Read, Bootstrap: f.Bootstrap, Fence: model.CapacityNativeWorkerAllocatorFenceObservation{ObservedAt: f.Now, Enforcement: []model.CapacityNativeWorkerFenceEnforcement{{ObservedAt: f.Now}}}, ValidUntil: f.Now.Add(time.Hour), Physical: &NativeWorkerMemberPhysicalFact{ObservedAt: f.Now}}
	facts.Observation.Configuration.ObservedAt = f.Now.Add(-12 * time.Second)
	if until := NativeWorkerMemberFactsValidUntil(f.Policy, f.Attempt, facts); !until.Equal(f.Now.Add(18 * time.Second)) {
		t.Fatal("fresh outer GET renewed old configz", until)
	}
	facts.Bootstrap.ObservedAt = f.Now.Add(-20 * time.Second)
	if until := NativeWorkerMemberFactsValidUntil(f.Policy, f.Attempt, facts); !until.Equal(f.Now.Add(10 * time.Second)) {
		t.Fatal("fresh outer GET renewed old guest", until)
	}
	f.Attempt.QualificationValidUntil = f.Now.Add(-time.Hour)
	if until := NativeWorkerMemberFactsValidUntil(f.Policy, f.Attempt, facts); !until.Equal(f.Now.Add(10 * time.Second)) {
		t.Fatal("old creation qualification became a lifetime placement deadline", until)
	}
	facts.Physical.ObservedAt = f.Now.Add(-27 * time.Second)
	if until := NativeWorkerMemberFactsValidUntil(f.Policy, f.Attempt, facts); !until.Equal(f.Now.Add(3 * time.Second)) {
		t.Fatal("current physical fact did not cap receiving", until)
	}
	facts.Observation.Inventory.Phase.Candidates[0].Heartbeat.ObservedAt = f.Now.Add(-29 * time.Second)
	if until := NativeWorkerMemberFactsValidUntil(f.Policy, f.Attempt, facts); !until.Equal(f.Now.Add(time.Second)) {
		t.Fatal("new outer GET renewed the old Node heartbeat", until)
	}
	facts.Physical = nil
	if !NativeWorkerMemberFactsValidUntil(f.Policy, f.Attempt, facts).IsZero() {
		t.Fatal("missing current physical read acquired a fact lifetime")
	}

	// Reuse the existing AWS original-plus-independent-read fixture, rather
	// than inventing a hetzner witness or claiming a generic fixture is AWS.
	p, a, launch, original, observed, now := nativePhysicalFixture(t)
	b := p.NativeWorkerLifecycleBinding.PhysicalObservers[0]
	qualified, err := PureNativePhysicalQualify(a, launch, original, observed, b, 30, now)
	if err != nil {
		t.Fatal("original AWS qualification fixture failed", err)
	}
	a.Physical = &qualified.IndependentCurrent
	p.NativeWorkerLifecycleBinding.Members = f.Policy.NativeWorkerLifecycleBinding.Members
	physical := NativeWorkerMemberPhysicalFact{Physical: *a.Physical, Adapter: b.Adapter, SourceCommit: b.SourceCommit, ScopeSHA256: b.ScopeSHA256, EvidenceSHA256: observed.EvidenceSHA256, ObservedAt: now}
	if !NativeWorkerMemberPhysicalFactValid(p, a, &physical, now) {
		t.Fatal("sealed current physical read refused")
	}
	for _, fault := range []string{"Source", "scope", "identity", "future", "stale"} {
		t.Run("physical_"+fault, func(t *testing.T) {
			bad := physical
			switch fault {
			case "Source":
				bad.SourceCommit = strings.Repeat("0", 40)
			case "scope":
				bad.ScopeSHA256 = marketTestSHA("0")
			case "identity":
				bad.Physical.ResourceID = "i-1123456789abcdef0"
			case "future":
				bad.ObservedAt = now.Add(time.Second)
			case "stale":
				bad.ObservedAt = now.Add(-30 * time.Second)
			}
			if NativeWorkerMemberPhysicalFactValid(p, a, &bad, now) {
				t.Fatal("current physical scope/identity/freshness was not bound")
			}
		})
	}

	object := model.CapacityNativeWorkerFenceObject{APIVersion: "admissionregistration.k8s.io/v1", Kind: "ValidatingAdmissionPolicy", Name: "native-fence", UID: marketTestUUID(980), ResourceVersion: "fence-rv", Generation: 1, PublicContentSHA256: marketTestSHA("8")}
	f.Authority.FenceObjects = []model.CapacityNativeWorkerFenceObject{object}
	f.Authority.Enforcement = []model.CapacityNativeWorkerFenceEnforcement{{APIServerID: "ci-api", PolicyUID: object.UID, Operation: "CREATE", SubjectName: "fixed-canary", Principal: "fixed-unqualified-node", ObservedAt: f.Now, HTTPStatus: 403, Reason: "Source fence refused"}}
	f.Authority.LegacyControllers = []model.CapacityNativeWorkerLegacyController{}
	pool := f.Policy.NativeWorkerPoolBinding
	fc := model.CapacityNativeWorkerAllocatorFenceContext{Schema: model.CapacityNativeWorkerAllocatorFenceContextSchema, CreatorPermitID: f.Attempt.ID.String(), AttemptID: f.Attempt.ID.String(), CoreSourceCommit: f.Attempt.SourceCommit, Observer: NativeWorkerMemberEndpoint(f.Policy.NativeWorkerLifecycleBinding.Members.AllocatorFenceReader, "observe_native_worker_allocator_fence"), PolicyID: f.Attempt.PolicyID.String(), PolicyChecksum: f.Attempt.PolicyChecksum, IntentGeneration: f.Attempt.Generation, FencingToken: f.Attempt.FencingToken, RealmUID: pool.RealmUID, PoolUID: pool.PoolUID, Owner: pool.Owner, Epoch: pool.ExpectedPoolEpoch, BootstrapPolicySHA256: f.Context.BootstrapPolicySHA256, NotAfter: f.Now.Add(-time.Minute)}
	raw, _ := json.Marshal(fc)
	fo := model.CapacityNativeWorkerAllocatorFenceObservation{Schema: model.CapacityNativeWorkerAllocatorFenceObservationSchema, BindingName: fc.Observer.BindingName, CreatorPermitID: fc.CreatorPermitID, SourceCommit: fc.Observer.SourceCommit, ScopeSHA256: fc.Observer.ScopeSHA256, Adapter: fc.Observer.Adapter, ContextSHA256: nativePrivateSHA(raw), ObservedAt: f.Now, Objects: f.Authority.FenceObjects, Enforcement: f.Authority.Enforcement, LegacyControllers: f.Authority.LegacyControllers, ProducerInventoryComplete: true, Complete: true}
	if NativeWorkerAllocatorFenceValid(f.Policy, fc, fo, f.Authority, f.Now) || !NativeWorkerMemberCurrentFenceValid(f.Policy, fc, fo, f.Authority, f.Now) {
		t.Fatal("current fence read renewed an expired creator right, or rejected installed current facts")
	}
	missingNode := f.Context
	missingNode.Node = nil
	if NativeWorkerPlacementBootstrapValid(f.Policy, f.Attempt, missingNode, f.Bootstrap, f.Authority, f.Now) {
		t.Fatal("nil Node accepted as a guest identity")
	}
	for _, age := range []time.Duration{-time.Second, 0, 7 * time.Second, 30 * time.Second, 31 * time.Second} {
		t.Run("canary_age_"+age.String(), func(t *testing.T) {
			read := fo
			read.Enforcement = append([]model.CapacityNativeWorkerFenceEnforcement(nil), fo.Enforcement...)
			read.Enforcement[0].ObservedAt = f.Now.Add(-age)
			authority := f.Authority
			authority.Enforcement = append([]model.CapacityNativeWorkerFenceEnforcement(nil), read.Enforcement...)
			valid := age >= 0 && age < 30*time.Second
			if NativeWorkerMemberCurrentFenceValid(f.Policy, fc, read, authority, f.Now) != valid {
				t.Fatal("coherent authority/read lost original canary freshness", age)
			}
			if age == 0 {
				before := read
				before.ObservedAt = f.Now.Add(-time.Second)
				if NativeWorkerMemberCurrentFenceValid(f.Policy, fc, before, authority, f.Now) {
					t.Fatal("canary after the completed outer read accepted")
				}
			}
			bounded := NativeWorkerMemberFacts{Observation: f.copy(t).Read, Bootstrap: f.Bootstrap, Fence: read, ValidUntil: f.Now.Add(time.Hour), Physical: &NativeWorkerMemberPhysicalFact{ObservedAt: f.Now}}
			if age >= 0 {
				want := f.Now.Add(30*time.Second - age)
				if got := NativeWorkerMemberFactsValidUntil(f.Policy, f.Attempt, bounded); !got.Equal(want) {
					t.Fatal("fresh outer GET renewed original canary time", got, want)
				}
			}
			if age == 7*time.Second {
				later := f.Now.Add(23 * time.Second)
				read.ObservedAt = later // A new read does not rerun the old canary.
				if NativeWorkerMemberCurrentFenceValid(f.Policy, fc, read, authority, later) {
					t.Fatal("outer refresh hid an expired original canary")
				}
			}
		})
	}
	emptyCanaries := NativeWorkerMemberFacts{Observation: f.copy(t).Read, Bootstrap: f.Bootstrap, Fence: fo, ValidUntil: f.Now.Add(time.Hour), Physical: &NativeWorkerMemberPhysicalFact{ObservedAt: f.Now}}
	if !NativeWorkerMemberFactsValidUntil(f.Policy, f.Attempt, emptyCanaries).After(f.Now) {
		t.Fatal("missing-canary negative lost its positive baseline")
	}
	emptyCanaries.Fence.Enforcement = nil
	if !NativeWorkerMemberFactsValidUntil(f.Policy, f.Attempt, emptyCanaries).IsZero() {
		t.Fatal("missing canary acquired a fact lifetime")
	}
	for _, fault := range []string{"Source", "Attempt"} {
		badContext, badRead := fc, fo
		if fault == "Source" {
			badContext.CoreSourceCommit = strings.Repeat("0", 40)
		} else {
			badContext.AttemptID = marketTestUUID(999)
		}
		raw, _ := json.Marshal(badContext)
		badRead.ContextSHA256 = nativePrivateSHA(raw)
		if NativeWorkerMemberCurrentFenceValid(f.Policy, badContext, badRead, f.Authority, f.Now) {
			t.Fatal("rehashed allocator context lost its original Source/Attempt", fault)
		}
	}
	fo.Objects = append([]model.CapacityNativeWorkerFenceObject(nil), fo.Objects...)
	fo.Objects[0].UID = marketTestUUID(999)
	if NativeWorkerMemberCurrentFenceValid(f.Policy, fc, fo, f.Authority, f.Now) {
		t.Fatal("read-selected fence object replaced protected installation identity")
	}
}

func TestNativeWorkerMemberCurrentReadbackNeverReopensPreimage(t *testing.T) {
	for _, effect := range []string{"NoSchedule", "NoExecute"} {
		t.Run("unmodeled_taint_"+effect, func(t *testing.T) {
			f := newMemberBindFixture(t)
			f.Read.Inventory.Phase.Candidates[0].Taints = append(f.Read.Inventory.Phase.Candidates[0].Taints, model.CapacityNativeWorkerPhaseTaint{Key: "maintenance.example/block", Value: "operator", Effect: effect})
			if NativeWorkerMemberObservationValid(f.Policy, f.Attempt, f.Context, f.Read, f.Authority, f.Now, false) == nil {
				t.Fatal("unmodeled blocking taint authorized a new Bind")
			}
			if err := NativeWorkerMemberCurrentObservationValid(f.Policy, f.Attempt, f.Context, f.Read, f.Authority, f.Now); err != nil {
				t.Fatal("non-authorizing receiving could not report current taint", err)
			}
			if f.Read.MutationAuthorized || f.Read.Inventory.MutationAuthorized {
				t.Fatal("current taint read claimed a new right")
			}
		})
	}
	for _, action := range []string{"bind_pod", "cordon"} {
		t.Run(action, func(t *testing.T) {
			f := newMemberFactsFixture(t, false)
			if action == "bind_pod" {
				f = newMemberBindFixture(t)
			}
			sealed, _ := json.Marshal(f.Context)
			f.Read.Inventory.Phase.Candidates[0].NodeResourceVersion = "new-node-rv"
			f.Read.Configuration.NodeResourceVersion = "new-node-rv"
			if action == "bind_pod" {
				f.Read.SubjectPod.Identity.ResourceVersion = "new-pod-rv"
				f.Read.SubjectPod.NodeName = f.Context.Node.Name
				f.Read.SubjectPod.Phase = "Running"
				f.Read.Pods = []model.CapacityNativeWorkerMemberPodFact{*f.Read.SubjectPod}
				f.Read.Inventory.TargetActivePods = 1
			} else {
				f.Read.Inventory.Phase.Candidates[0].Unschedulable = true
			}
			f.reseal()
			if NativeWorkerMemberObservationValid(f.Policy, f.Attempt, f.Context, f.Read, f.Authority, f.Now, false) == nil {
				t.Fatal("post-effect GET became the old writer preimage")
			}
			if err := NativeWorkerMemberCurrentObservationValid(f.Policy, f.Attempt, f.Context, f.Read, f.Authority, f.Now); err != nil {
				t.Fatal("same-identity current readback refused", err)
			}
			after, _ := json.Marshal(f.Context)
			if !bytes.Equal(sealed, after) || f.Read.MutationAuthorized || f.Read.Inventory.MutationAuthorized || f.Read.Inventory.Phase.UsefulCapacityQualified {
				t.Fatal("receiving renewed authority or asserted useful capacity")
			}
			f.Read.Inventory.Phase.Candidates[0].NodeUID = marketTestUUID(999)
			if NativeWorkerMemberCurrentObservationValid(f.Policy, f.Attempt, f.Context, f.Read, f.Authority, f.Now) == nil {
				t.Fatal("relaxed RV check also relaxed immutable NodeUID")
			}
		})
	}
}

func TestNativeWorkerMemberRosterDigestIsCanonicalWithoutMutation(t *testing.T) {
	f := newMemberFactsFixture(t, false)
	pods := []model.CapacityNativeWorkerMemberPodFact{f.pod("z-last", 970), f.pod("a-first", 971)}
	// Even rejected/finalizing facts have a stable safe digest; hashing them
	// is not a validator or permission to remove the finalizers.
	pods[0].Finalizers = []string{"z.example/finalizer", "a.example/finalizer"}
	pods[0].PDBs = []model.CapacityNativeWorkerMemberPDB{{Namespace: "business", Name: "z", UID: marketTestUUID(972)}, {Namespace: "business", Name: "a", UID: marketTestUUID(973)}}
	before, _ := json.Marshal(pods)
	first := NativeWorkerMemberPodRosterSHA(pods)
	after, _ := json.Marshal(pods)
	if !ValidDigest(first) || !bytes.Equal(before, after) {
		t.Fatal("roster hashing mutated caller-owned slices")
	}
	var reordered []model.CapacityNativeWorkerMemberPodFact
	if json.Unmarshal(before, &reordered) != nil {
		t.Fatal("copy roster")
	}
	reordered[0], reordered[1] = reordered[1], reordered[0]
	reordered[1].Finalizers[0], reordered[1].Finalizers[1] = reordered[1].Finalizers[1], reordered[1].Finalizers[0]
	reordered[1].PDBs[0], reordered[1].PDBs[1] = reordered[1].PDBs[1], reordered[1].PDBs[0]
	if first != NativeWorkerMemberPodRosterSHA(reordered) {
		t.Fatal("equivalent collection order changed safe digest")
	}
	reordered[0].Identity.UID = marketTestUUID(999)
	if first == NativeWorkerMemberPodRosterSHA(reordered) || reflect.DeepEqual(pods, reordered) {
		t.Fatal("identity substitution did not change roster digest")
	}
}
