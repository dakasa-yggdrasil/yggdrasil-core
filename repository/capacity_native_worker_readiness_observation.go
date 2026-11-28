package repository

import (
	"net/netip"
	"reflect"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// Runtime image IDs must be children of the independently received normal
// publication, not merely copies of the requested image or a loopback claim.
type nativeReadinessObservationPins struct {
	Binding                                 model.CapacityNativeWorkerReadinessBinding
	ProbeContainerName, CoreContainerName   string
	ProbeRuntimeDigests, CoreRuntimeDigests []string
	FloorName, FloorUID, FloorProviderID    string
	RegistryUID, RegistrationBindingSHA256  string
	PodCIDR, ServiceCIDR                    string
	MaxAge                                  time.Duration
}

func nativeReadinessObservationHeader(r nativeReadinessRun, pins nativeReadinessObservationPins, o model.NativeWorkerProbeResourceObservation, slot, uid string, now time.Time) error {
	b := pins.Binding.ResourceReader
	name, kind, exists := nativeReadinessSlot(r, slot)
	if kind == "StartupChallenge" {
		kind = "Pod"
	}
	api := "v1"
	if kind == "NetworkPolicy" {
		api = "networking.k8s.io/v1"
	}
	want := o.EvidenceSHA256
	o.EvidenceSHA256 = ""
	actual, err := nativeReadinessDigest(o)
	if !exists || !nativeReadinessSHA(want) || err != nil || actual != want || o.Schema != model.NativeWorkerProbeResourceObservationSchema || o.SourceCommit != b.SourceCommit || o.BindingScopeSHA256 != b.ScopeSHA256 || o.Adapter != b.Adapter || o.BindingName != b.Name || o.RunID != r.ID.String() || o.Slot != slot || !o.ReadComplete || o.MutationAuthorized || o.ReadinessQualified || o.AbsenceProven || o.ObservedAt.Before(r.CreatedAt) || o.ObservedAt.After(now) || pins.MaxAge <= 0 || now.Sub(o.ObservedAt) >= pins.MaxAge || o.Namespace.APIVersion != "v1" || o.Namespace.Kind != "Namespace" || o.Namespace.Namespace != "" || o.Namespace.Name != pins.Binding.Namespace || o.Namespace.UID != pins.Binding.NamespaceUID || !nativeReadinessResourceVersion(o.Namespace.ResourceVersion) || o.Namespace.Deleting || o.Resource.APIVersion != api || o.Resource.Kind != kind || o.Resource.Name != name || o.Resource.Namespace != pins.Binding.Namespace {
		return errNativeReadinessRun
	}
	if !o.Found {
		// This is only a fresh exact-name GET result. Closure additionally needs
		// the original journal UID and a consumed delete, checked by the caller.
		if o.HTTPStatus != 404 || uid == "" || o.Resource.UID != "" || o.Resource.ResourceVersion != "" || o.AttemptID != "" || o.Pod != nil || o.Node != nil || o.Service != nil {
			return errNativeReadinessRun
		}
		return nil
	}
	if o.HTTPStatus != 200 || o.AttemptID != r.Identity.AttemptID.String() || o.Resource.UID != uid || !nativeReadinessCanonicalUUID(uid) || !nativeReadinessResourceVersion(o.Resource.ResourceVersion) || o.Resource.Deleting || o.Resource.CreatedAt.IsZero() || o.Resource.CreatedAt.Before(r.CreatedAt.Truncate(time.Second)) || o.Resource.CreatedAt.After(o.ObservedAt) || (kind == "Secret") != o.SecretMetadataOnly {
		return errNativeReadinessRun
	}
	return nil
}

func nativeReadinessRuntimeImage(actual string, digests []string) bool {
	if i := strings.LastIndex(actual, "@"); i >= 0 {
		actual = actual[i+1:]
	}
	for _, prefix := range []string{"docker-pullable://", "docker://", "containerd://"} {
		actual = strings.TrimPrefix(actual, prefix)
	}
	if !strings.HasPrefix(actual, "sha256:") || !nativeReadinessSHA(strings.TrimPrefix(actual, "sha256:")) {
		return false
	}
	for _, allowed := range digests {
		if actual == allowed {
			return true
		}
	}
	return false
}

func nativeReadinessPod(r nativeReadinessRun, a model.CapacityNativeWorkerAttempt, pins nativeReadinessObservationPins, o model.NativeWorkerProbeResourceObservation, role string, coreReady bool) error {
	if !o.Found || o.Pod == nil || o.Node == nil || o.Service != nil || o.SecretMetadataOnly || o.Pod.Phase != "Running" || o.Pod.NodeName != o.Node.Name || o.Node.Deleting || o.Pod.ContainerName != pins.ProbeContainerName || o.Pod.Image != pins.Binding.ProbeImage || !nativeReadinessRuntimeImage(o.Pod.ImageID, pins.ProbeRuntimeDigests) || o.Pod.RestartCount != 0 || !o.Pod.Running || o.Pod.ContainerID == "" || o.Pod.StartedAt.Before(r.CreatedAt.Truncate(time.Second)) || o.Pod.StartedAt.After(o.ObservedAt) {
		return errNativeReadinessRun
	}
	address, e := netip.ParseAddr(o.Pod.PodIPv4)
	pods, pe := netip.ParsePrefix(pins.PodCIDR)
	if e != nil || !address.Is4() || address.String() != o.Pod.PodIPv4 || pe != nil || !pods.Contains(address) || !nativeReadinessResourceVersion(o.Node.ResourceVersion) {
		return errNativeReadinessRun
	}
	count := 1
	if role == "candidate" {
		count = 2
		n := o.Node
		if a.Physical == nil || n.UID != a.NodeUID || n.ProviderID != a.Physical.ProviderID || !n.RegistrationFound || n.RegistrationEpoch != a.PoolEpoch || n.Profile != a.Profile || n.PhysicalSpecSHA256 != a.PhysicalSpecSHA256 || n.RegistrationBindingSHA256 != pins.RegistrationBindingSHA256 || n.CapacityPolicyID != a.PolicyID.String() || n.IntentGeneration != a.Generation || n.FencingToken != a.FencingToken || n.CreationProofSHA256 != a.BirthSHA256 || n.RegistryUID != pins.RegistryUID || !nativeReadinessResourceVersion(n.RegistryResourceVersion) {
			return errNativeReadinessRun
		}
	} else if role != "floor" || o.Node.Name != pins.FloorName || o.Node.UID != pins.FloorUID || o.Node.ProviderID != pins.FloorProviderID {
		return errNativeReadinessRun
	}
	if len(o.Pod.Containers) != count {
		return errNativeReadinessRun
	}
	seen := map[string]bool{}
	for _, c := range o.Pod.Containers {
		if seen[c.Name] || c.ContainerID == "" || c.RestartCount != 0 || !c.Running || c.StartedAt.Before(r.CreatedAt.Truncate(time.Second)) || c.StartedAt.After(o.ObservedAt) {
			return errNativeReadinessRun
		}
		seen[c.Name] = true
		switch c.Name {
		case pins.ProbeContainerName:
			if c.Image != pins.Binding.ProbeImage || !nativeReadinessRuntimeImage(c.ImageID, pins.ProbeRuntimeDigests) || c.ContainerID != o.Pod.ContainerID || c.StartedAt != o.Pod.StartedAt {
				return errNativeReadinessRun
			}
		case pins.CoreContainerName:
			if role != "candidate" || c.Image != pins.Binding.CoreWorkerImage || !nativeReadinessRuntimeImage(c.ImageID, pins.CoreRuntimeDigests) || coreReady && !c.Ready {
				return errNativeReadinessRun
			}
		default:
			return errNativeReadinessRun
		}
	}
	if !seen[pins.ProbeContainerName] || role == "candidate" && !seen[pins.CoreContainerName] {
		return errNativeReadinessRun
	}
	return nil
}

func nativeReadinessService(r nativeReadinessRun, pins nativeReadinessObservationPins, service, pod model.NativeWorkerProbeResourceObservation, role string) error {
	if !service.Found || service.Service == nil || service.Pod != nil || service.Node != nil || !service.EndpointSlicesComplete || !nativeReadinessResourceVersion(service.EndpointSliceCollectionResourceVersion) || service.Service.Type != "ClusterIP" || service.Service.SelectorRunID != r.ID.String() || pod.Pod == nil || service.Service.SelectorSlot != role+"_pod" || len(service.Service.Ports) != 1 || len(service.EndpointSlices) != 1 {
		return errNativeReadinessRun
	}
	ip, e := netip.ParseAddr(service.Service.ClusterIPv4)
	network, ne := netip.ParsePrefix(pins.ServiceCIDR)
	if e != nil || !ip.Is4() || ip.String() != service.Service.ClusterIPv4 || ne != nil || !network.Contains(ip) {
		return errNativeReadinessRun
	}
	port := service.Service.Ports[0]
	if port.Name != "probe-udp" || port.Protocol != "UDP" || port.Port != 9446 || port.TargetPort != "9446" {
		return errNativeReadinessRun
	}
	slice := service.EndpointSlices[0]
	if !nativeReadinessCanonicalUUID(slice.UID) || !nativeReadinessResourceVersion(slice.ResourceVersion) || slice.OwnerServiceUID != service.Resource.UID || slice.AddressType != "IPv4" || len(slice.Ports) != 1 || slice.Ports[0].Name != port.Name || slice.Ports[0].Protocol != port.Protocol || slice.Ports[0].Port != port.Port || slice.Ports[0].TargetPort != "" || len(slice.Endpoints) != 1 {
		return errNativeReadinessRun
	}
	x := slice.Endpoints[0]
	if len(x.Addresses) != 1 || x.Addresses[0] != pod.Pod.PodIPv4 || x.NodeName != pod.Pod.NodeName || (x.TargetAPIVersion != "" && x.TargetAPIVersion != "v1") || x.TargetKind != "Pod" || x.TargetNamespace != pins.Binding.Namespace || x.TargetName != pod.Resource.Name || x.TargetUID != pod.Resource.UID || x.Terminating != nil && *x.Terminating {
		return errNativeReadinessRun
	}
	// publishNotReadyAddresses deliberately keeps this diagnostic endpoint
	// usable before the worker opens roots. EndpointReady is not warmup proof.
	return nil
}

func nativeReadinessSamePod(before, after model.NativeWorkerProbeResourceObservation) bool {
	if before.Pod == nil || after.Pod == nil || before.Node == nil || after.Node == nil || before.Resource.UID != after.Resource.UID || !before.Resource.CreatedAt.Equal(after.Resource.CreatedAt) || before.Resource.Name != after.Resource.Name || before.Resource.Namespace != after.Resource.Namespace || before.Pod.PodIPv4 != after.Pod.PodIPv4 || before.Pod.NodeName != after.Pod.NodeName || before.Node.UID != after.Node.UID || before.Node.ProviderID != after.Node.ProviderID || before.Node.RegistryUID != after.Node.RegistryUID || before.Node.RegistrationEpoch != after.Node.RegistrationEpoch || before.Node.CreationProofSHA256 != after.Node.CreationProofSHA256 || len(before.Pod.Containers) != len(after.Pod.Containers) {
		return false
	}
	// Ready may legitimately change after the real startup handshake. Neither
	// a heartbeat RV nor opaque collection RV is a process identity substitute.
	left, right := map[string]model.NativeWorkerProbeContainerObservation{}, map[string]model.NativeWorkerProbeContainerObservation{}
	for _, x := range before.Pod.Containers {
		x.Ready = false
		left[x.Name] = x
	}
	for _, x := range after.Pod.Containers {
		x.Ready = false
		right[x.Name] = x
	}
	return reflect.DeepEqual(left, right)
}
