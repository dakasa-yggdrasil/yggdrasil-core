package capacity

import (
	"encoding/json"
	"net/netip"
	"strings"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// NativeWorkerNetworkSelector projects only the five public reader selectors
// from the exact immutable stored launch. It performs no I/O and grants no
// mutation, physical, network or readiness authority. Real receiving still
// requires NativeWorkerNetworkPreparationValidForAction with actual facts.
func NativeWorkerNetworkSelector(p model.CapacityPolicySpec, a model.CapacityNativeWorkerAttempt, raw json.RawMessage) (model.CapacityNativeWorkerNetworkObserveInput, error) {
	var zero model.CapacityNativeWorkerNetworkObserveInput
	if ValidateNativeWorkerNetworkBinding(p) != nil || p.NativeWorkerLifecycleBinding == nil || p.NativeWorkerLifecycleBinding.Network == nil || p.NativeWorkerPoolBinding == nil ||
		a.ID == uuid.Nil || a.PolicyID == uuid.Nil || a.SourceCommit != p.NativeWorkerLifecycleBinding.SourceCommit {
		return zero, errNativeWorkerNetworkRPC
	}
	b, pool := p.NativeWorkerLifecycleBinding.Network, p.NativeWorkerPoolBinding
	var launch nativePrivateLaunch
	if len(raw) == 0 || len(raw) > 32768 || nativePrivateSHA(raw) != a.LaunchSHA256 || DecodeNativeCapacity(raw, &launch) != nil ||
		launch.Schema != 1 || launch.Mode != "native_k3s_worker_v1" || launch.Network.Mode != "wireguard_routed_v1" ||
		a.PoolUID != pool.PoolUID || a.PoolEpoch != pool.ExpectedPoolEpoch || a.Registry != pool.RegistryRef ||
		launch.ReservationID != a.ID.String() || launch.PolicyID != a.PolicyID.String() || launch.PolicySHA256 != strings.TrimPrefix(a.PolicyChecksum, "sha256:") ||
		launch.PoolUID != a.PoolUID || launch.ExpectedPoolEpoch != a.PoolEpoch || launch.IntentGeneration != a.Generation || launch.FencingToken != a.FencingToken || launch.IntentSHA256 != a.IntentSHA256 ||
		launch.Registry.Kind != a.Registry.Kind || launch.Registry.Namespace != a.Registry.Namespace || launch.Registry.Name != a.Registry.Name || launch.Registry.UID != a.Registry.UID ||
		launch.SourceCommit != b.Template.GuestSystemSourceCommit || launch.Network.TransportCIDR != b.Template.TransportCIDR || launch.Network.PodCIDR != b.Template.PodCIDR || launch.Network.ServiceCIDR != b.Template.ServiceCIDR ||
		launch.Network.WorkerIPv4 != a.OverlayIPv4 || launch.Network.FloorPeerIPv4 != b.Template.FloorPeerIPv4 || launch.Network.FloorPeerPublicKey != b.Template.FloorPublicKey ||
		launch.Floor.NodeName != b.Floor.NodeName || launch.Floor.NodeUID != b.Floor.NodeUID || launch.Floor.ProviderID != b.Floor.ProviderID || launch.Floor.ClusterUID != b.Floor.ClusterUID || launch.Floor.CASHA256 != b.Floor.CASHA256 ||
		!nativeWorkerNetworkKey(launch.Network.WorkerPublicKey) || launch.Network.WorkerPublicKey == b.Template.FloorPublicKey {
		return zero, errNativeWorkerNetworkRPC
	}
	ip, err := netip.ParseAddr(a.OverlayIPv4)
	prefix, _ := netip.ParsePrefix(b.Template.TransportCIDR)
	if err != nil || !ip.Is4() || ip.String() != a.OverlayIPv4 || !prefix.Contains(ip) || ip == prefix.Addr() || a.OverlayIPv4 == b.Template.FloorPeerIPv4 {
		return zero, errNativeWorkerNetworkRPC
	}
	return model.CapacityNativeWorkerNetworkObserveInput{BindingName: b.Reader.BindingName, AttemptID: a.ID.String(), LaunchSHA256: a.LaunchSHA256, WorkerPublicKey: launch.Network.WorkerPublicKey, WorkerIPv4: a.OverlayIPv4}, nil
}
