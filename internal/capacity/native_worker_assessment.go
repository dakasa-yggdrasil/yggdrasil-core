package capacity

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

const ObserveNativeWorkerPool = "observe_native_worker_pool"
const ObserveComputeOffer = "observe_compute_offer"

// NativeWorkerPoolSnapshot counts independently joined Ready Nodes, never a
// process, VM acceptance, registration request, HPA bound or protected floor.
func NativeWorkerPoolSnapshot(p model.CapacityPolicySpec, observation *model.CapacityNativeWorkerPoolObservation, now time.Time) (model.CapacitySnapshot, error) {
	var out model.CapacitySnapshot
	if p.NativeWorkerPoolBinding == nil {
		return out, fmt.Errorf("native worker pool binding required")
	}
	b := *p.NativeWorkerPoolBinding
	summary, err := SummarizeNativeWorkerPool(b, observation, b.ExpectedPoolEpoch, now)
	if err != nil {
		return out, err
	}
	if summary.RegisteredUnits != summary.ReadyUnits {
		return out, fmt.Errorf("registered native workers are not all useful Ready capacity")
	}
	if !knownProfile(p, observation.CurrentProfile) {
		return out, fmt.Errorf("registry current profile unavailable")
	}
	for _, node := range observation.Nodes {
		if node.Profile != observation.CurrentProfile {
			return out, fmt.Errorf("mixed native pool requires its explicit overlap lifecycle")
		}
	}
	return model.CapacitySnapshot{TargetIdentity: p.TargetIdentity, ResourceUID: b.RegistryRef.UID, ResourceVersion: observation.CollectionResourceVersion, WorkloadUID: b.PoolUID, WorkloadResourceVersion: observation.OwnerResourceVersion, Owner: p.Owner, Profile: observation.CurrentProfile, Units: summary.ReadyUnits, ObservedAt: observation.ObservedAt}, nil
}

// This digest is explicitly semantic comparison evidence, never a native RV.
// Current source timestamps and native RVs remain in the original observation.
func NativeWorkerPoolSemanticFingerprint(o *model.CapacityNativeWorkerPoolObservation) (string, error) {
	if o == nil {
		return "", fmt.Errorf("native worker observation required")
	}
	stable := *o
	stable.OwnerResourceVersion, stable.CollectionResourceVersion, stable.EvidenceSHA256 = "", "", ""
	stable.ObservedAt = time.Time{}
	stable.Nodes = append([]model.CapacityNativeWorkerNode{}, o.Nodes...)
	for i := range stable.Nodes {
		n := &stable.Nodes[i]
		n.NodeResourceVersion, n.AdmissionRegistryResourceVersion = "", ""
		n.ReadyObservedAt = time.Time{}
	}
	sort.Slice(stable.Nodes, func(i, j int) bool { return stable.Nodes[i].NodeUID < stable.Nodes[j].NodeUID })
	raw, err := json.Marshal(stable)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", sha256.Sum256(raw)), nil
}
