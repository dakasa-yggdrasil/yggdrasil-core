package capacity

import (
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

const NativeWorkerMemberMode = "native_worker_member_v1"
const NativeWorkerReservedTaint = "dakasa.io/native-worker-reserved"

var ErrNativeWorkerMember = errors.New("native member facts or authority unavailable")

func ValidateNativeWorkerMemberBinding(p model.CapacityPolicySpec) error {
	l := p.NativeWorkerLifecycleBinding
	if l == nil || l.Members == nil {
		return nil
	}
	b := l.Members
	if b.Mode != NativeWorkerMemberMode || !marketID.MatchString(b.Name) || !ValidDigest(b.BootstrapPolicySHA256) || b.MaxPermitSeconds < 1 || b.MaxPermitSeconds > model.CapacityNativeWorkerMemberMaxPermitSeconds || b.MaxReadAgeSeconds < 1 || b.MaxReadAgeSeconds > model.CapacityNativeWorkerMemberMaxGuestAgeSeconds || p.NativeWorkerPoolBinding == nil || l.PhaseObserver == nil || l.RegistryWriter == nil || l.PreAdmissionAbort == nil || l.Network == nil {
		return ErrNativeWorkerMember
	}
	used := map[string]bool{p.NativeWorkerPoolBinding.Adapter.ManifestID: true, l.PhaseObserver.Adapter.ManifestID: true, l.RegistryWriter.Adapter.ManifestID: true}
	for _, e := range l.Profiles {
		used[e.Adapter.ManifestID] = true
		if !ValidDigest(e.GuestIdentityPolicySHA256) {
			return ErrNativeWorkerMember
		}
	}
	for _, e := range []model.CapacityNativeWorkerProbeResourceBinding{b.Writer, b.Reader, b.AllocatorFenceReader} {
		if !marketAdapterValid(e.Adapter) || !marketID.MatchString(e.Name) || !marketCommit.MatchString(e.SourceCommit) || !ValidDigest(e.ScopeSHA256) || used[e.Adapter.ManifestID] {
			return ErrNativeWorkerMember
		}
		used[e.Adapter.ManifestID] = true
	}
	if !marketID.MatchString(b.Writer.PrincipalID) || b.Reader.PrincipalID != "" || b.AllocatorFenceReader.PrincipalID != "" || b.Writer.ScopeSHA256 == b.Reader.ScopeSHA256 || b.Writer.ScopeSHA256 == b.AllocatorFenceReader.ScopeSHA256 || b.Reader.ScopeSHA256 == b.AllocatorFenceReader.ScopeSHA256 {
		return ErrNativeWorkerMember
	}
	return nil
}

func NativeWorkerMemberEndpoint(b model.CapacityNativeWorkerProbeResourceBinding, cap string) model.CapacityNativeWorkerMemberEndpoint {
	return model.CapacityNativeWorkerMemberEndpoint{Adapter: b.Adapter, BindingName: b.Name, SourceCommit: b.SourceCommit, ScopeSHA256: b.ScopeSHA256, Capability: cap}
}
func NativeWorkerMemberCapability(action, plan string) string {
	switch action {
	case "cordon":
		if plan == "retirement" {
			return "ensure_native_worker_pool_member"
		}
	case "bind_pod":
		if plan == "placement" {
			return "ensure_native_worker_pod_placement"
		}
	case "evict_pod":
		if plan == "placement" {
			return "destroy_native_worker_pod_placement"
		}
		if plan == "retirement" {
			return "destroy_native_worker_pool_member"
		}
	case "delete_node", "retire_registry":
		if plan == "retirement" {
			return "destroy_native_worker_pool_member"
		}
	}
	return ""
}
func NativeWorkerMemberReadCapability(action string) string {
	if action == "bind_pod" {
		return "observe_native_worker_pod_placement"
	}
	return "observe_native_worker_pool_member"
}
func NativeWorkerMemberContextSHA(c model.CapacityNativeWorkerMemberContext) string {
	raw, _ := json.Marshal(c)
	return nativePrivateSHA(raw)
}
func nativeMemberUUID(raw string) bool {
	u, e := uuid.Parse(raw)
	return e == nil && u != uuid.Nil && u.String() == raw
}
func nativeMemberFresh(at, now time.Time, age int) bool {
	return age > 0 && !at.IsZero() && !at.After(now) && now.Sub(at) < time.Duration(age)*time.Second
}

// This validates the sealed identity, not the history-derived Mode or grant.
// The journal derives Mode under the shared Attempt lock before calling this.
// Historical identity remains readable after NotAfter; only Store Redeem checks
// the database clock and grants a live operation. This never renews a Context.
func NativeWorkerMemberContextValid(p model.CapacityPolicySpec, a model.CapacityNativeWorkerAttempt, c model.CapacityNativeWorkerMemberContext, now time.Time, seed bool) error {
	if ValidateNativeWorkerMemberBinding(p) != nil || p.NativeWorkerLifecycleBinding == nil || p.NativeWorkerLifecycleBinding.Members == nil || p.NativeWorkerPoolBinding == nil || a.Physical == nil || !NativeWorkerPhysicalValid(a, *a.Physical) {
		return ErrNativeWorkerMember
	}
	l, b, pool := p.NativeWorkerLifecycleBinding, p.NativeWorkerLifecycleBinding.Members, p.NativeWorkerPoolBinding
	name, e := NativeWorkerBootstrapNodeName(a)
	plan := "retirement"
	if c.Action == "bind_pod" || c.Actor.Capability == "destroy_native_worker_pod_placement" {
		plan = "placement"
	}
	cap := NativeWorkerMemberCapability(c.Action, plan)
	if e != nil || cap == "" || c.Schema != model.CapacityNativeWorkerMemberContextSchema || !nativeMemberUUID(c.PlanID) || !nativeMemberUUID(c.PermitID) || c.AttemptID != a.ID.String() || c.CoreSourceCommit != a.SourceCommit || c.CoreSourceCommit != l.SourceCommit || c.PolicyID != a.PolicyID.String() || c.PolicyChecksum != a.PolicyChecksum || c.IntentGeneration != a.Generation || c.FencingToken != a.FencingToken || c.RealmNamespace != pool.RegistryRef.Namespace || c.RealmUID != pool.RealmUID || c.PoolUID != a.PoolUID || c.PoolUID != pool.PoolUID || c.Owner != pool.Owner || c.Owner != p.Owner || c.Epoch != a.PoolEpoch || c.Epoch != pool.ExpectedPoolEpoch || c.Profile != a.Profile || c.BirthSHA256 != a.BirthSHA256 || !ValidDigest(c.BirthSHA256) || c.Physical != *a.Physical || c.OverlayIPv4 != a.OverlayIPv4 || c.Registry != a.Registry || c.Actor != NativeWorkerMemberEndpoint(b.Writer, cap) || c.Observer != NativeWorkerMemberEndpoint(b.Reader, NativeWorkerMemberReadCapability(c.Action)) || c.BootstrapPolicySHA256 != b.BootstrapPolicySHA256 || c.NotAfter.IsZero() || c.Node == nil || c.Node.Name != name || c.Node.ProviderID != a.Physical.ProviderID {
		return ErrNativeWorkerMember
	}
	if c.Mode != "never_admitted" && c.Mode != "admitted" || c.Action == "bind_pod" && c.Mode != "admitted" || c.Mode == "admitted" && !ValidDigest(c.AdmissionReceiptSHA256) || c.Mode == "never_admitted" && c.AdmissionReceiptSHA256 != "" {
		return ErrNativeWorkerMember
	}
	if !seed && (!nativeMemberUUID(c.Node.UID) || c.Node.ResourceVersion == "" || !ValidDigest(c.PlacementFenceSHA256)) || a.NodeUID != "" && c.Node.UID != a.NodeUID {
		return ErrNativeWorkerMember
	}
	if c.Node.UID != "" && !nativeMemberUUID(c.Node.UID) {
		return ErrNativeWorkerMember
	}
	for _, floor := range pool.ProtectedNodes {
		if c.Node.UID == floor.NodeUID || c.Physical.ProviderID == floor.ProviderID {
			return ErrNativeWorkerMember
		}
	}
	podAction := c.Action == "bind_pod" || c.Action == "evict_pod"
	if podAction != (c.Pod != nil) {
		return ErrNativeWorkerMember
	}
	if c.Pod != nil && (!nativeMemberUUID(c.Pod.UID) || !marketDNSLabel.MatchString(c.Pod.Name) || !marketDNSLabel.MatchString(c.Pod.Namespace) || !seed && c.Pod.ResourceVersion == "") {
		return ErrNativeWorkerMember
	}
	if c.Action == "retire_registry" && (c.RegistryResourceVersion == "" || !ValidDigest(c.RegistrySHA256) || !ValidDigest(c.NodeAbsenceEvidenceSHA256)) || (c.Action == "delete_node" || c.Action == "retire_registry") && !ValidDigest(c.PhysicalAbsenceEvidenceSHA256) {
		return ErrNativeWorkerMember
	}
	return nil
}

// Hash a copy. Sorting never changes the retained original projection. The old
// Inventory nonterminal digest remains byte-exact and independent of this one.
func NativeWorkerMemberPodRosterSHA(pods []model.CapacityNativeWorkerMemberPodFact) string {
	raw, e := json.Marshal(pods)
	if e != nil {
		return ""
	}
	var own []model.CapacityNativeWorkerMemberPodFact
	if json.Unmarshal(raw, &own) != nil {
		return ""
	}
	for i := range own {
		slices.Sort(own[i].Finalizers)
		slices.Sort(own[i].StorageKinds)
		sort.Slice(own[i].PDBs, func(x, y int) bool {
			a, b := own[i].PDBs[x], own[i].PDBs[y]
			return a.Namespace+"/"+a.Name+"/"+a.UID < b.Namespace+"/"+b.Name+"/"+b.UID
		})
	}
	sort.Slice(own, func(i, j int) bool {
		a, b := own[i].Identity, own[j].Identity
		return a.Namespace+"/"+a.Name+"/"+a.UID < b.Namespace+"/"+b.Name+"/"+b.UID
	})
	raw, e = json.Marshal(own)
	if e != nil {
		return ""
	}
	return nativePrivateSHA(raw)
}

func nativeMemberPodValid(p model.CapacityNativeWorkerMemberPodFact, authority NativeWorkerMemberAuthority, node string, evict bool) bool {
	x := p.Identity
	if !strings.HasPrefix(x.Name, "nw-") || !nativeMemberUUID(x.UID) || !marketDNSLabel.MatchString(x.Namespace) || !marketDNSLabel.MatchString(x.Name) || x.ResourceVersion == "" || p.NodeName != node || p.Phase == "" || p.Mirror || !p.ContractMatched || !slices.Contains(authority.WorkloadContracts, p.ContractID) || p.TerminationGraceSeconds < 0 || p.TerminationGraceSeconds > 120 || p.Finalizers == nil || len(p.Finalizers) != 0 || p.Controllers == nil || len(p.Controllers) != 2 || p.PDBs == nil || len(p.PDBs) > 1 || p.StorageKinds == nil || p.VolumeAttachmentsPresent {
		return false
	}
	if p.Controllers[0].APIVersion != "apps/v1" || p.Controllers[0].Kind != "ReplicaSet" || p.Controllers[1].APIVersion != "apps/v1" || p.Controllers[1].Kind != "Deployment" || !strings.HasPrefix(p.Controllers[1].Name, "nw-") {
		return false
	}
	expected, known := authority.WorkloadLineage[p.ContractID]
	if !known || len(expected) != len(p.Controllers) {
		return false
	}
	for i, c := range p.Controllers {
		want := expected[i]
		if c.APIVersion != want.APIVersion || c.Kind != want.Kind || c.Namespace != want.Namespace || c.Name != want.Name || c.UID != want.UID || c.Generation != want.Generation {
			return false
		}
		if c.APIVersion == "" || c.Kind == "" || c.Namespace != x.Namespace || c.Name == "" || !nativeMemberUUID(c.UID) || c.ResourceVersion == "" || c.Generation < 1 || c.ObservedGeneration < c.Generation || i > 0 && c.UID == p.Controllers[i-1].UID {
			return false
		}
	}
	for _, kind := range p.StorageKinds {
		if !slices.Contains([]string{"secret", "config_map", "projected", "downward_api", "empty_dir"}, kind) {
			return false
		}
	}
	for _, b := range p.PDBs {
		if b.Namespace != x.Namespace || b.Name == "" || !nativeMemberUUID(b.UID) || b.ResourceVersion == "" || b.Generation < 1 || b.ObservedGeneration < b.Generation || b.DisruptedPods == nil || evict && b.DisruptionsAllowed < 1 {
			return false
		}
		if _, ok := b.DisruptedPods[x.Name]; ok {
			return false
		}
	}
	return !evict || !p.Deleting
}

func nativeMemberPhasePolicy(p model.CapacityPolicySpec) model.CapacityPolicySpec {
	l := *p.NativeWorkerLifecycleBinding
	b := l.Members.Reader
	l.PhaseObserver = &model.CapacityNativeWorkerPhaseReadBinding{Mode: NativeWorkerPhaseReadMode, Name: b.Name, SourceCommit: b.SourceCommit, Adapter: b.Adapter, ScopeSHA256: b.ScopeSHA256, RealmNamespace: p.NativeWorkerPoolBinding.RegistryRef.Namespace, MaxAgeSeconds: l.Members.MaxReadAgeSeconds, QuarantineTaintKey: l.PhaseObserver.QuarantineTaintKey}
	p.NativeWorkerLifecycleBinding = &l
	return p
}

// Complete safe projections are facts only. A custody verifier separately
// parses the private configz original and requires equality before grant issue.
func NativeWorkerMemberObservationValid(p model.CapacityPolicySpec, a model.CapacityNativeWorkerAttempt, c model.CapacityNativeWorkerMemberContext, o model.CapacityNativeWorkerMemberObservation, authority NativeWorkerMemberAuthority, now time.Time, seed bool) error {
	return nativeWorkerMemberObservationValid(p, a, c, o, authority, now, seed, false)
}

// Receiving checks current facts without requiring the old writer preimage RV
// or an unbound SubjectPod. It grants no right and cannot renew the Context.
func NativeWorkerMemberCurrentObservationValid(p model.CapacityPolicySpec, a model.CapacityNativeWorkerAttempt, c model.CapacityNativeWorkerMemberContext, o model.CapacityNativeWorkerMemberObservation, authority NativeWorkerMemberAuthority, now time.Time) error {
	return nativeWorkerMemberObservationValid(p, a, c, o, authority, now, false, true)
}
func nativeWorkerMemberObservationValid(p model.CapacityPolicySpec, a model.CapacityNativeWorkerAttempt, c model.CapacityNativeWorkerMemberContext, o model.CapacityNativeWorkerMemberObservation, authority NativeWorkerMemberAuthority, now time.Time, seed, after bool) error {
	if NativeWorkerMemberContextValid(p, a, c, now, seed) != nil {
		return ErrNativeWorkerMember
	}
	b := p.NativeWorkerLifecycleBinding.Members
	in, phase := o.Inventory, o.Inventory.Phase
	bound := nativeMemberPhasePolicy(p)
	want := model.CapacityNativeWorkerAbortInventoryRequest{BindingName: b.Reader.Name, ProviderID: c.Physical.ProviderID, CreationProofSHA256: c.BirthSHA256, NodeName: c.Node.Name}
	if o.Schema != model.CapacityNativeWorkerMemberObservationSchema || o.BindingName != b.Reader.Name || o.PermitID != c.PermitID || o.SourceCommit != b.Reader.SourceCommit || o.ScopeSHA256 != b.Reader.ScopeSHA256 || o.Adapter != b.Reader.Adapter || o.ContextSHA256 != NativeWorkerMemberContextSHA(c) || !nativeMemberUUID(o.ReadID) || !nativeMemberFresh(o.ObservedAt, now, b.MaxReadAgeSeconds) || !o.Complete || o.MutationAuthorized || o.Pods == nil || len(o.Pods) > model.CapacityNativeWorkerMemberMaxPods || !o.ControllerReadsComplete || !o.PDBReadsComplete || !o.StorageReadsComplete || !ValidDigest(o.PodRosterSHA256) || o.PodRosterSHA256 != NativeWorkerMemberPodRosterSHA(o.Pods) || in.Schema != "native_worker_abort_inventory_v1" || in.BindingName != b.Reader.Name || in.SourceCommit != b.Reader.SourceCommit || in.Adapter != b.Reader.Adapter || in.BindingScopeSHA256 != b.Reader.ScopeSHA256 || in.Requested != want || !in.Complete || !in.PodsComplete || !in.PodsAllNamespaces || in.MutationAuthorized || in.PodCollectionVersion == "" || !ValidDigest(in.BeforePhaseEvidence) || !ValidDigest(in.TargetPodEvidenceSHA256) || !ValidDigest(in.EvidenceSHA256) || !nativeMemberFresh(in.ObservedAt, now, b.MaxReadAgeSeconds) || in.ObservedAt.After(o.ObservedAt) || NativeWorkerPhaseHeaderValid(bound, phase, now) != nil || !phase.CandidateSelected || phase.RequestedProviderID != c.Physical.ProviderID || phase.RequestedCreationProofSHA256 != c.BirthSHA256 {
		return ErrNativeWorkerMember
	}
	active := 0
	uids := map[string]bool{}
	for _, pod := range o.Pods {
		if !nativeMemberPodValid(pod, authority, c.Node.Name, false) || uids[pod.Identity.UID] {
			return ErrNativeWorkerMember
		}
		uids[pod.Identity.UID] = true
		if pod.Phase != "Succeeded" && pod.Phase != "Failed" {
			active++
		}
	}
	if active != in.TargetActivePods {
		return ErrNativeWorkerMember
	}
	if c.Action == "retire_registry" && !seed && !after && (c.RegistryResourceVersion != phase.Registry.ResourceVersion || c.RegistrySHA256 != phase.Registry.AnnotationSHA256) {
		return ErrNativeWorkerMember
	}
	if c.Action == "bind_pod" {
		if o.SubjectPod == nil || o.SubjectPod.Identity.UID != c.Pod.UID || o.SubjectPod.Identity.Name != c.Pod.Name || o.SubjectPod.Identity.Namespace != c.Pod.Namespace || !seed && !after && o.SubjectPod.Identity.ResourceVersion != c.Pod.ResourceVersion || !nativeMemberPodValid(*o.SubjectPod, authority, o.SubjectPod.NodeName, false) || !after && (o.SubjectPod.NodeName != "" || o.SubjectPod.Deleting || uids[c.Pod.UID]) || after && o.SubjectPod.NodeName != "" && o.SubjectPod.NodeName != c.Node.Name {
			return ErrNativeWorkerMember
		}
	} else if o.SubjectPod != nil {
		return ErrNativeWorkerMember
	}
	if c.Action == "evict_pod" && !after {
		found := false
		for _, pod := range o.Pods {
			if pod.Identity.UID == c.Pod.UID && pod.Identity.Namespace == c.Pod.Namespace && pod.Identity.Name == c.Pod.Name && (seed || pod.Identity.ResourceVersion == c.Pod.ResourceVersion) && nativeMemberPodValid(pod, authority, c.Node.Name, true) {
				found = true
			}
		}
		if !found {
			return ErrNativeWorkerMember
		}
	}

	admitted := false
	for _, entry := range phase.Registrations {
		if entry.ProviderID != c.Physical.ProviderID && entry.NodeUID != c.Node.UID {
			continue
		}
		if entry.ProviderID != c.Physical.ProviderID || entry.CreationProofSHA256 != c.BirthSHA256 || c.Node.UID != "" && entry.NodeUID != c.Node.UID || entry.CapacityPolicyID != c.PolicyID || entry.IntentGeneration != c.IntentGeneration || entry.FencingToken != c.FencingToken || entry.Profile != c.Profile || entry.PhysicalSpecSHA256 != a.PhysicalSpecSHA256 {
			return ErrNativeWorkerMember
		}
		if entry.Admission.State == "admitted" {
			if admitted || entry.Admission.ReceiptSHA256 != c.AdmissionReceiptSHA256 {
				return ErrNativeWorkerMember
			}
			admitted = true
		}
	}
	if c.Mode == "admitted" && !admitted || c.Mode == "never_admitted" && admitted {
		return ErrNativeWorkerMember
	}
	if phase.CandidateAbsenceProven {
		if c.Action != "retire_registry" && !(after && c.Action == "delete_node") || len(phase.Candidates) != 0 || len(o.Pods) != 0 || o.Configuration != nil {
			return ErrNativeWorkerMember
		}
		return nil
	}
	if len(phase.Candidates) != 1 {
		return ErrNativeWorkerMember
	}
	n := phase.Candidates[0]
	if n.NodeName != c.Node.Name || n.ProviderID != c.Node.ProviderID || !nativeMemberUUID(n.NodeUID) || !seed && n.NodeUID != c.Node.UID || !seed && !after && n.NodeResourceVersion != c.Node.ResourceVersion || n.NodeResourceVersion == "" || n.PoolUIDLabel != c.PoolUID {
		return ErrNativeWorkerMember
	}

	internal := 0
	for _, address := range n.Addresses {
		if address.Type == "InternalIP" {
			if address.Address != c.OverlayIPv4 {
				return ErrNativeWorkerMember
			}
			internal++
		}
	}
	if internal != 1 {
		return ErrNativeWorkerMember
	}
	for _, claim := range [][2]string{{n.CreationProofSHA256Label, c.BirthSHA256}, {n.ProfileLabel, c.Profile}, {n.PhysicalSpecSHA256Label, a.PhysicalSpecSHA256}, {n.PolicyIDLabel, c.PolicyID}} {
		if c.Mode == "admitted" && claim[0] != claim[1] || claim[0] != "" && claim[0] != claim[1] {
			return ErrNativeWorkerMember
		}
	}
	reserved, quarantine := false, false
	for _, t := range n.Taints {
		if c.Action == "bind_pod" && !after && t.Key != NativeWorkerReservedTaint && (t.Effect == "NoSchedule" || t.Effect == "NoExecute") {
			return ErrNativeWorkerMember
		}
		if t.Key == NativeWorkerReservedTaint {
			if reserved || t.Value != c.PoolUID || t.Effect != "NoSchedule" {
				return ErrNativeWorkerMember
			}
			reserved = true
		}
		if t.Key == bound.NativeWorkerLifecycleBinding.PhaseObserver.QuarantineTaintKey {
			if quarantine || t.Value != c.PoolUID || t.Effect != "NoSchedule" {
				return ErrNativeWorkerMember
			}
			quarantine = true
		}
		if t.Key == "node.cloudprovider.kubernetes.io/uninitialized" {
			return ErrNativeWorkerMember
		}
	}
	if !reserved || c.Mode == "never_admitted" && !quarantine || c.Action == "bind_pod" && !after && (quarantine || !nativePhaseReady(bound, c.Profile, n, now) || n.Unschedulable || n.Deleting) {
		return ErrNativeWorkerMember
	}
	if c.Action == "delete_node" {
		if len(o.Pods) != 0 || o.Configuration != nil || !n.Unschedulable {
			return ErrNativeWorkerMember
		}
		return nil
	}
	config := o.Configuration
	if config == nil || config.Schema != model.CapacityNativeWorkerKubeConfigurationSchema || config.NodeName != n.NodeName || config.NodeUID != n.NodeUID || config.NodeResourceVersion != n.NodeResourceVersion || config.KubeletVersion != "v1.34.6+k3s1" || config.KubeletVersion != authority.KubeletVersion || config.EndpointIPv4 != c.OverlayIPv4 || !ValidDigest(config.ServerLeafSHA256) || !config.ConfigurationPresent || !config.ReadComplete || config.HTTPStatus != 200 || config.StaticPodPath != "" || config.StaticPodURL != "" || config.PrivateOriginalRef != o.ReadID || !nativeMemberFresh(config.ObservedAt, now, b.MaxReadAgeSeconds) || config.ObservedAt.After(o.ObservedAt) {
		return ErrNativeWorkerMember
	}
	return nil
}

func NativeWorkerPlacementBootstrapValid(p model.CapacityPolicySpec, a model.CapacityNativeWorkerAttempt, c model.CapacityNativeWorkerMemberContext, o model.CapacityNativeWorkerPlacementBootstrapObservation, authority NativeWorkerMemberAuthority, now time.Time) bool {
	if ValidateNativeWorkerMemberBinding(p) != nil || p.NativeWorkerLifecycleBinding == nil || p.NativeWorkerLifecycleBinding.Members == nil || c.Node == nil {
		return false
	}
	b := p.NativeWorkerLifecycleBinding.Members
	if o.Schema != model.CapacityNativeWorkerPlacementBootstrapSchema || o.SourceCommit != authority.SystemSourceCommit || o.SourceCommit != a.Execution.BootstrapSourceCommit || o.AttemptID != a.ID.String() || o.LaunchSHA256 != a.LaunchSHA256 || o.ProviderID != c.Physical.ProviderID || o.NodeName != c.Node.Name || !nativeMemberFresh(o.ObservedAt, now, b.MaxReadAgeSeconds) || o.AgentPID < 1 || o.AgentStartTicks < 1 || !o.AgentConfigComplete || o.AgentConfigPath != authority.AgentConfigPath || !reflect.DeepEqual(o.ConfiguredKubeletArgs, authority.ConfiguredKubeletArgs) || o.ConfiguredNodeIPv4 != a.OverlayIPv4 {
		return false
	}
	for _, arg := range []string{"pod-manifest-path=", "manifest-url=", "cloud-provider="} {
		if !slices.Contains(o.ConfiguredKubeletArgs, arg) {
			return false
		}
	}
	// K3s may replace its original cmdline with this single safe process title.
	return reflect.DeepEqual(o.ActualAgentArgv, []string{"/usr/local/bin/k3s agent"}) || reflect.DeepEqual(o.ActualAgentArgv, []string{"/usr/local/bin/k3s", "agent", "--config", authority.AgentConfigPath})
}

func NativeWorkerAllocatorFenceValid(p model.CapacityPolicySpec, c model.CapacityNativeWorkerAllocatorFenceContext, o model.CapacityNativeWorkerAllocatorFenceObservation, a NativeWorkerMemberAuthority, now time.Time) bool {
	return c.NotAfter.After(now) && nativeWorkerCurrentAllocatorFenceValid(p, c, o, a, now)
}

// A current read of installed fencing can remain useful after the creator
// command expires. This is not pre-create permission and never renews it.
func NativeWorkerMemberCurrentFenceValid(p model.CapacityPolicySpec, c model.CapacityNativeWorkerAllocatorFenceContext, o model.CapacityNativeWorkerAllocatorFenceObservation, a NativeWorkerMemberAuthority, now time.Time) bool {
	return nativeWorkerCurrentAllocatorFenceValid(p, c, o, a, now)
}
func nativeWorkerCurrentAllocatorFenceValid(p model.CapacityPolicySpec, c model.CapacityNativeWorkerAllocatorFenceContext, o model.CapacityNativeWorkerAllocatorFenceObservation, a NativeWorkerMemberAuthority, now time.Time) bool {
	if p.NativeWorkerLifecycleBinding == nil || p.NativeWorkerLifecycleBinding.Members == nil || p.NativeWorkerPoolBinding == nil {
		return false
	}
	b := p.NativeWorkerLifecycleBinding.Members
	pool := p.NativeWorkerPoolBinding
	if c.CoreSourceCommit != p.NativeWorkerLifecycleBinding.SourceCommit || !nativeMemberUUID(c.AttemptID) || c.CreatorPermitID != c.AttemptID || !nativeMemberUUID(c.PolicyID) || !ValidDigest(c.PolicyChecksum) || c.IntentGeneration < 1 || c.FencingToken < 1 || c.Schema != model.CapacityNativeWorkerAllocatorFenceContextSchema || c.Observer != NativeWorkerMemberEndpoint(b.AllocatorFenceReader, "observe_native_worker_allocator_fence") || c.PoolUID != pool.PoolUID || c.RealmUID != pool.RealmUID || c.Owner != pool.Owner || c.Epoch != pool.ExpectedPoolEpoch || c.BootstrapPolicySHA256 != b.BootstrapPolicySHA256 || c.NotAfter.IsZero() || o.Schema != model.CapacityNativeWorkerAllocatorFenceObservationSchema || o.BindingName != c.Observer.BindingName || o.CreatorPermitID != c.CreatorPermitID || o.SourceCommit != c.Observer.SourceCommit || o.ScopeSHA256 != c.Observer.ScopeSHA256 || o.Adapter != c.Observer.Adapter || !nativeMemberFresh(o.ObservedAt, now, b.MaxReadAgeSeconds) || !o.Complete || o.MutationAuthorized || !o.ProducerInventoryComplete || len(a.FenceObjects) == 0 || len(a.Enforcement) == 0 || a.LegacyControllers == nil || !reflect.DeepEqual(o.Objects, a.FenceObjects) || !reflect.DeepEqual(o.Enforcement, a.Enforcement) || !reflect.DeepEqual(o.LegacyControllers, a.LegacyControllers) {
		return false
	}
	raw, _ := json.Marshal(c)
	if o.ContextSHA256 != nativePrivateSHA(raw) {
		return false
	}
	for _, obj := range o.Objects {
		if !nativeMemberUUID(obj.UID) || obj.ResourceVersion == "" || !ValidDigest(obj.PublicContentSHA256) {
			return false
		}
	}
	for _, e := range o.Enforcement {
		if e.HTTPStatus != 403 || e.Reason == "" || !nativeMemberFresh(e.ObservedAt, now, b.MaxReadAgeSeconds) || e.ObservedAt.After(o.ObservedAt) {
			return false
		}
	}
	return true
}

// Semantic evidence hashes never contain configz bytes, its raw digest, tokens
// or unredacted commands. Full raw originals remain in encrypted custody.
func NativeWorkerMemberFactsSHA(f NativeWorkerMemberFacts) string {
	raw, err := json.Marshal(f)
	if err != nil {
		return ""
	}
	return nativePrivateSHA(raw)
}

func NativeWorkerMemberFactsValidUntil(p model.CapacityPolicySpec, a model.CapacityNativeWorkerAttempt, f NativeWorkerMemberFacts) time.Time {
	if p.NativeWorkerLifecycleBinding == nil || p.NativeWorkerLifecycleBinding.Members == nil {
		return time.Time{}
	}
	age := time.Duration(p.NativeWorkerLifecycleBinding.Members.MaxReadAgeSeconds) * time.Second
	until := f.ValidUntil
	for _, at := range []time.Time{f.Observation.ObservedAt, f.Observation.Inventory.ObservedAt, f.Observation.Inventory.Phase.ObservedAt, f.Bootstrap.ObservedAt, f.Fence.ObservedAt} {
		if at.IsZero() {
			return time.Time{}
		}
		end := at.Add(age)
		if until.IsZero() || end.Before(until) {
			until = end
		}
	}
	if len(f.Fence.Enforcement) == 0 {
		return time.Time{}
	}
	for _, e := range f.Fence.Enforcement {
		if e.ObservedAt.IsZero() {
			return time.Time{}
		}
		end := e.ObservedAt.Add(age)
		if end.Before(until) {
			until = end
		}
	}
	if cfg := f.Observation.Configuration; cfg != nil {
		end := cfg.ObservedAt.Add(age)
		if cfg.ObservedAt.IsZero() {
			return time.Time{}
		}
		if end.Before(until) {
			until = end
		}
	}
	if f.Physical == nil || f.Physical.ObservedAt.IsZero() {
		return time.Time{}
	}
	end := f.Physical.ObservedAt.Add(age)
	if end.Before(until) {
		until = end
	}
	for _, n := range f.Observation.Inventory.Phase.Candidates {
		if n.Heartbeat.ObservedAt.IsZero() {
			return time.Time{}
		}
		end := n.Heartbeat.ObservedAt.Add(age)
		if end.Before(until) {
			until = end
		}
	}
	return until
}

func NativeWorkerMemberPhysicalFactValid(p model.CapacityPolicySpec, a model.CapacityNativeWorkerAttempt, f *NativeWorkerMemberPhysicalFact, now time.Time) bool {
	if f == nil || a.Physical == nil || f.Physical != *a.Physical || p.NativeWorkerLifecycleBinding == nil || p.NativeWorkerLifecycleBinding.Members == nil || !NativeWorkerPhysicalValid(a, f.Physical) || !ValidDigest(f.EvidenceSHA256) || !nativeMemberFresh(f.ObservedAt, now, p.NativeWorkerLifecycleBinding.Members.MaxReadAgeSeconds) {
		return false
	}
	matches := 0
	for _, b := range p.NativeWorkerLifecycleBinding.PhysicalObservers {
		if b.Profile == a.Profile && b.Provider == a.Provider && b.Region == a.Region && b.Adapter == f.Adapter && b.SourceCommit == f.SourceCommit && b.ScopeSHA256 == f.ScopeSHA256 {
			matches++
		}
	}
	return matches == 1
}
