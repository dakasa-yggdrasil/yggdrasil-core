package capacity

import (
	"strconv"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// Abort inventory uses a separate read-only process and whole-file scope.
// Its nested phase observations are checked against that exact binding, not
// against the independent admission observer's file or credentials.
func NativeWorkerAbortInventoryPolicy(p model.CapacityPolicySpec) (model.CapacityPolicySpec, error) {
	if p.NativeWorkerLifecycleBinding == nil || p.NativeWorkerLifecycleBinding.PreAdmissionAbort == nil || p.NativeWorkerLifecycleBinding.AbortInventoryObserver == nil {
		return model.CapacityPolicySpec{}, errNativeCleanup
	}
	life := *p.NativeWorkerLifecycleBinding
	life.PhaseObserver = life.AbortInventoryObserver
	p.NativeWorkerLifecycleBinding = &life
	if ValidateNativeWorkerPhaseReadBinding(p) != nil {
		return model.CapacityPolicySpec{}, errNativeCleanup
	}
	return p, nil
}

// Every nonterminal Pod counts. A missing Node, missing Lease, or expired
// provider permit never substitutes for the complete original-name inventory.
func NativeWorkerApplyAbortInventory(p model.CapacityPolicySpec, a model.CapacityNativeWorkerAttempt, in model.CapacityNativeWorkerAbortInventoryObservation, o model.CapacityNativeWorkerAbortObservation, now time.Time) (model.CapacityNativeWorkerAbortObservation, error) {
	zero := model.CapacityNativeWorkerAbortObservation{}
	bound, err := NativeWorkerAbortInventoryPolicy(p)
	if err != nil || a.Physical == nil {
		return zero, errNativeCleanup
	}
	b, pool := bound.NativeWorkerLifecycleBinding.PhaseObserver, bound.NativeWorkerPoolBinding
	name, err := NativeWorkerBootstrapNodeName(a)
	want := model.CapacityNativeWorkerAbortInventoryRequest{BindingName: b.Name, ProviderID: a.Physical.ProviderID, CreationProofSHA256: a.BirthSHA256, NodeName: name}
	phase := in.Phase
	if err != nil || in.Schema != "native_worker_abort_inventory_v1" || in.SourceCommit != b.SourceCommit || in.BindingScopeSHA256 != b.ScopeSHA256 || in.Adapter != b.Adapter || in.BindingName != b.Name || in.Requested != want ||
		!in.Complete || !in.PodsComplete || !in.PodsAllNamespaces || in.MutationAuthorized || in.PodCollectionVersion == "" || in.TargetActivePods < 0 ||
		!ValidDigest(in.BeforePhaseEvidence) || !ValidDigest(in.TargetPodEvidenceSHA256) || !ValidDigest(in.EvidenceSHA256) || in.ObservedAt.After(now) || !fresh(in.ObservedAt, now, b.MaxAgeSeconds) ||
		NativeWorkerPhaseHeaderValid(bound, phase, now) != nil || !phase.CandidateSelected || phase.RequestedProviderID != want.ProviderID || phase.RequestedCreationProofSHA256 != a.BirthSHA256 || phase.ObservedAt.After(in.ObservedAt) ||
		a.PoolUID != pool.PoolUID || a.PoolEpoch != pool.ExpectedPoolEpoch || a.Registry != pool.RegistryRef || a.PolicyChecksum == "" {
		return zero, errNativeCleanup
	}
	registration := ""
	for _, profile := range pool.Profiles {
		if profile.Profile == a.Profile {
			registration = profile.RegistrationBindingSHA
		}
	}
	if !ValidDigest(registration) {
		return zero, errNativeCleanup
	}
	o.RealmUID, o.PoolUID, o.Owner, o.Epoch = pool.RealmUID, pool.PoolUID, pool.Owner, pool.ExpectedPoolEpoch
	o.Registry, o.RegistryResourceVersion, o.ExecutionScopeSHA256 = pool.RegistryRef, phase.Registry.ResourceVersion, a.Execution.ScopeSHA256
	o.Physical = *a.Physical
	o.NodesComplete, o.PodsComplete, o.ApplicationPods = true, true, in.TargetActivePods
	o.NodeEvidenceSHA256, o.RegistryEvidenceSHA256 = in.EvidenceSHA256, phase.EvidenceSHA256
	o.RegistryEntryAbsent = true
	admitted := false
	for _, entry := range phase.Registrations {
		if entry.ProviderID != a.Physical.ProviderID && (a.NodeUID == "" || entry.NodeUID != a.NodeUID) {
			continue
		}
		if !o.RegistryEntryAbsent || entry.ProviderID != a.Physical.ProviderID || a.NodeUID != "" && entry.NodeUID != a.NodeUID ||
			entry.Profile != a.Profile || entry.CapacityPolicyID != a.PolicyID.String() || entry.CreationProofSHA256 != a.BirthSHA256 || entry.PhysicalSpecSHA256 != a.PhysicalSpecSHA256 ||
			entry.RegistrationBindingSHA256 != registration || entry.IntentGeneration != a.Generation || entry.FencingToken != a.FencingToken {
			return zero, errNativeCleanup
		}
		o.RegistryEntryAbsent = false
		admitted = entry.Admission.State == "admitted"
	}
	if len(phase.Candidates) == 0 {
		if !phase.CandidateAbsenceProven || admitted {
			return zero, errNativeCleanup
		}
		o.NodeState = "none_confirmed"
		o.NodeUID, o.NodeProviderID, o.NodeResourceVersion = "", "", ""
		o.QuarantinePresent, o.Unschedulable = false, false
		return o, nil
	}
	if len(phase.Candidates) != 1 || phase.CandidateAbsenceProven {
		return zero, errNativeCleanup
	}
	n := phase.Candidates[0]
	if !marketUUID.MatchString(n.NodeUID) || n.NodeName != name || n.NodeResourceVersion == "" || n.ProviderID != a.Physical.ProviderID || a.NodeUID != "" && n.NodeUID != a.NodeUID ||
		n.PoolUIDLabel != a.PoolUID {
		return zero, errNativeCleanup
	}
	// Before register_quarantined the Source bootstrap need not yet carry the
	// registry writer's optional labels. Existing claims must match exactly.
	for _, claim := range [][2]string{{n.CreationProofSHA256Label, a.BirthSHA256}, {n.ProfileLabel, a.Profile}, {n.PhysicalSpecSHA256Label, a.PhysicalSpecSHA256}, {n.RegistrationBindingSHA256Label, registration}, {n.PolicyIDLabel, a.PolicyID.String()}, {n.GenerationLabel, strconv.FormatInt(a.Generation, 10)}, {n.FencingTokenLabel, strconv.FormatInt(a.FencingToken, 10)}} {
		if claim[0] != "" && claim[0] != claim[1] {
			return zero, errNativeCleanup
		}
	}
	for _, protected := range pool.ProtectedNodes {
		if n.NodeUID == protected.NodeUID || n.ProviderID == protected.ProviderID {
			return zero, errNativeCleanup
		}
	}
	quarantine, err := nativePhaseOwnedQuarantine(bound, n)
	if err != nil {
		return zero, errNativeCleanup
	}
	o.NodeUID, o.NodeProviderID, o.NodeResourceVersion = n.NodeUID, n.ProviderID, n.NodeResourceVersion
	o.QuarantinePresent, o.Unschedulable = quarantine, n.Unschedulable
	o.NodeState = "unknown"
	if admitted || !quarantine {
		o.NodeState = "admitted" // Never let a lost taint authorize pre-admission delete.
	} else {
		o.NodeState = "quarantined"
	}
	return o, nil
}
