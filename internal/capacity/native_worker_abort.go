package capacity

import (
	"fmt"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func ValidateNativeWorkerAbortBinding(p model.CapacityPolicySpec) error {
	if p.NativeWorkerLifecycleBinding == nil || p.NativeWorkerLifecycleBinding.PreAdmissionAbort == nil {
		return nil
	}
	b := p.NativeWorkerLifecycleBinding.PreAdmissionAbort
	if b.Mode != model.CapacityNativeWorkerAbortSchema || b.MaxPermitSeconds < 1 || b.MaxPermitSeconds > 300 ||
		b.Workflow.ManifestID != "" || b.Workflow.Version != nil || !marketID.MatchString(b.Workflow.Namespace) || !marketID.MatchString(b.Workflow.Name) {
		return fmt.Errorf("exact source-owned pre-admission cleanup workflow and bounded permit required")
	}
	if p.NativeWorkerLifecycleBinding.AbortInventoryObserver != nil {
		if _, err := NativeWorkerAbortInventoryPolicy(p); err != nil {
			return err
		}
	}
	return nil
}

// A missing or unhealthy Node is not a zero-node proof. Header validation also
// applies to unknown observations so the controller can retain honest custody.
func NativeWorkerAbortObservationValid(p model.CapacityPolicySpec, a model.CapacityNativeWorkerAttempt, o model.CapacityNativeWorkerAbortObservation, now time.Time) bool {
	b := p.NativeWorkerPoolBinding
	if b == nil || p.NativeWorkerLifecycleBinding == nil || a.Physical == nil || !ValidDigest(a.BirthSHA256) ||
		o.Physical != *a.Physical || !NativeWorkerPhysicalValid(a, o.Physical) || (o.Physical.AccountID == "" && a.Provider != "hetzner") ||
		o.RealmUID != b.RealmUID || o.PoolUID != a.PoolUID || o.PoolUID != b.PoolUID || o.Owner != b.Owner ||
		o.Epoch != a.PoolEpoch || o.Epoch != b.ExpectedPoolEpoch || o.Registry != a.Registry || o.Registry != b.RegistryRef ||
		o.RegistryResourceVersion == "" || o.ExecutionScopeSHA256 != a.Execution.ScopeSHA256 ||
		o.ObservedAt.After(now) || !fresh(o.ObservedAt, now, p.NativeWorkerLifecycleBinding.MaxReadAgeSeconds) || o.ApplicationPods < 0 {
		return false
	}
	if a.Provider == "hetzner" && !NativeWorkerHCloudWitnessBindingValid(p, a, a.HCloudWitness) {
		return false
	}
	for _, protected := range b.ProtectedNodes {
		if o.Physical.ProviderID == protected.ProviderID || o.NodeUID != "" && o.NodeUID == protected.NodeUID {
			return false
		}
	}
	switch o.ProviderOutcome {
	case "present", "not_found", "terminal_nonbillable", "unknown":
	default:
		return false
	}
	switch o.NodeState {
	case "none_confirmed":
		return o.NodesComplete && o.NodeUID == "" && o.NodeProviderID == "" && ValidDigest(o.NodeEvidenceSHA256)
	case "quarantined", "admitted":
		return marketUUID.MatchString(o.NodeUID) && (a.NodeUID == "" || o.NodeUID == a.NodeUID) &&
			o.NodeProviderID == o.Physical.ProviderID && o.NodeResourceVersion != "" && ValidDigest(o.NodeEvidenceSHA256)
	case "unknown", "ambiguous":
		return true
	}
	return false
}

func NativeWorkerAbortSendSafe(o model.CapacityNativeWorkerAbortObservation) bool {
	if o.ProviderOutcome != "present" || !ValidDigest(o.ProviderEvidenceSHA256) || !o.NodesComplete || !o.PodsComplete || o.ApplicationPods != 0 {
		return false
	}
	if o.ResourceFootprint != nil && o.ResourceFootprint.HCloud != nil {
		for _, ip := range o.ResourceFootprint.HCloud.PrimaryIPs {
			if !ip.AutoDelete || ip.DeleteProtected {
				return false // A separate IP writer is not part of server deletion.
			}
		}
	}
	return o.NodeState == "none_confirmed" || o.NodeState == "quarantined" && o.QuarantinePresent && o.Unschedulable
}

func NativeWorkerAbortSettled(o model.CapacityNativeWorkerAbortObservation) bool {
	if (o.ProviderOutcome != "not_found" && o.ProviderOutcome != "terminal_nonbillable") || !ValidDigest(o.ProviderEvidenceSHA256) ||
		o.NodeState != "none_confirmed" || !o.NodesComplete || !o.PodsComplete || o.ApplicationPods != 0 ||
		!ValidDigest(o.NodeEvidenceSHA256) || !o.RegistryEntryAbsent || !ValidDigest(o.RegistryEvidenceSHA256) ||
		!o.NetworkPeerAbsent || !o.IPAMEntryAbsent || !ValidDigest(o.NetworkEvidenceSHA256) ||
		!o.AncillaryChargesClosed || !ValidDigest(o.ChargeEvidenceSHA256) {
		return false
	}
	return true
}
