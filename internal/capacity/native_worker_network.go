package capacity

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

const NativeWorkerNetworkMode = "native_worker_floor_network_v1"
const NativeWorkerNetworkInstall = "ensure_native_worker_network"
const NativeWorkerNetworkRemove = "destroy_native_worker_network"
const ObserveNativeWorkerNetwork = "observe_native_worker_network"
const NativeWorkerNetworkMTU = 1380

// This is a protected Go runtime port, never accepted from a machine callback.
// Install requires a complete current independent provider observation. Remove
// uses the sealed birth target and the original installed endpoint retained by
// the repository; it never invents a live-provider observation after deletion.
type NativeWorkerNetworkPreparation struct {
	Floor                  model.CapacityNativeWorkerNetworkObservation
	Physical               model.CapacityNativeWorkerPhysical
	PhysicalObservedAt     time.Time
	PhysicalEvidenceSHA256 string
	PhysicalSourceCommit   string
	PhysicalScopeSHA256    string
	TransportEndpointIPv4  string
}

func NativeWorkerNetworkTemplateSHA256(t model.CapacityNativeWorkerNetworkTemplate) string {
	raw, _ := json.Marshal(t)
	return fmt.Sprintf("%x", sha256.Sum256(raw))
}

func nativeWorkerNetworkKey(s string) bool {
	b, e := base64.StdEncoding.DecodeString(s)
	if e != nil || len(b) != 32 || base64.StdEncoding.EncodeToString(b) != s {
		return false
	}
	var nonzero byte
	for _, v := range b {
		nonzero |= v
	}
	return nonzero != 0
}

func nativeWorkerNetworkPrefix(raw string) (netip.Prefix, bool) {
	p, e := netip.ParsePrefix(raw)
	return p, e == nil && p.Addr().Is4() && p.Addr().IsPrivate() && p == p.Masked() && p.String() == raw && p.Bits() >= 8 && p.Bits() <= 30
}

// An absent network binding retains the original policy wire and authority.
// The binding selects no provider resource, private material or shell command.
func ValidateNativeWorkerNetworkBinding(p model.CapacityPolicySpec) error {
	life, pool := p.NativeWorkerLifecycleBinding, p.NativeWorkerPoolBinding
	if life == nil || life.Network == nil {
		return nil
	}
	b := life.Network
	w, r, f, n := b.Writer, b.Reader, b.Floor, b.Template
	if b.Mode != NativeWorkerNetworkMode || pool == nil || life.PhaseObserver == nil || b.MaxPermitSeconds < 1 || b.MaxPermitSeconds > 120 ||
		!marketUUID.MatchString(w.AdapterID) || !marketUUID.MatchString(r.AdapterID) || w.AdapterID == r.AdapterID ||
		!marketDNSLabel.MatchString(w.BindingName) || !marketDNSLabel.MatchString(r.BindingName) || w.BindingName == r.BindingName ||
		w.PrincipalID == "" || len(w.PrincipalID) > 256 || strings.ContainsAny(w.PrincipalID, "\x00\r\n") ||
		!marketCommit.MatchString(w.SystemSourceCommit) || r.SystemSourceCommit != w.SystemSourceCommit ||
		!marketSHA.MatchString(w.ScopeSHA256) || !marketSHA.MatchString(r.ScopeSHA256) || w.ScopeSHA256 == r.ScopeSHA256 ||
		!marketSHA.MatchString(b.TemplateSHA256) || NativeWorkerNetworkTemplateSHA256(n) != b.TemplateSHA256 {
		return fmt.Errorf("separate exact Native network writer and reader binding required")
	}
	protected := false
	for _, node := range pool.ProtectedNodes {
		protected = protected || node.NodeUID == f.NodeUID && node.ProviderID == f.ProviderID
	}
	native, e := netip.ParseAddr(f.NativeIPv4)
	if !protected || !marketDNSLabel.MatchString(f.NodeName) || !marketUUID.MatchString(f.NodeUID) || f.ClusterUID != pool.RealmUID || !marketSHA.MatchString(f.CASHA256) ||
		e != nil || !native.Is4() || !native.IsPrivate() || native.String() != f.NativeIPv4 || f.NativeInterface != "enp7s0" || !validNativeProviderID("hcloud://", f.ProviderID) {
		return fmt.Errorf("actual protected floor and private interface binding required")
	}
	transport, transportOK := nativeWorkerNetworkPrefix(n.TransportCIDR)
	pods, podsOK := nativeWorkerNetworkPrefix(n.PodCIDR)
	services, servicesOK := nativeWorkerNetworkPrefix(n.ServiceCIDR)
	floor, floorErr := netip.ParseAddr(n.FloorPeerIPv4)
	dns, dnsErr := netip.ParseAddr(n.ClusterDNSIPv4)
	if n.Schema != 1 || n.GuestSystemSourceCommit != w.SystemSourceCommit || n.Interface != "wg-dakasa" || n.MTU != NativeWorkerNetworkMTU ||
		!transportOK || transport.Bits() < 16 || !podsOK || !servicesOK || transport.Overlaps(pods) || transport.Overlaps(services) || pods.Overlaps(services) ||
		transport.Contains(native) || pods.Contains(native) || services.Contains(native) ||
		floorErr != nil || !floor.Is4() || floor.String() != n.FloorPeerIPv4 || !transport.Contains(floor) || floor == transport.Addr() || floor == native ||
		dnsErr != nil || !dns.Is4() || dns.String() != n.ClusterDNSIPv4 || !services.Contains(dns) || dns == services.Addr() ||
		!nativeWorkerNetworkKey(n.FloorPublicKey) || n.ListenPort < 1024 || n.ListenPort > 65535 || n.FirewallChain != "DAKASA_NATIVE" ||
		n.DNSName != "kubernetes.default.svc.cluster.local" {
		return fmt.Errorf("exact separate Native network template required")
	}
	used := map[string]bool{pool.Adapter.ManifestID: true, life.PhaseObserver.Adapter.ManifestID: true}
	if life.RegistryWriter != nil {
		used[life.RegistryWriter.Adapter.ManifestID] = true
	}
	if p.MarketBinding != nil {
		for _, profile := range p.MarketBinding.Profiles {
			used[profile.Adapter.ManifestID] = true
		}
	}
	for _, physical := range life.PhysicalObservers {
		used[physical.Adapter.ManifestID] = true
	}
	for _, profile := range life.Profiles {
		used[profile.Adapter.ManifestID] = true
		if profile.OverlayCIDR != n.TransportCIDR || profile.BootstrapSourceCommit != n.GuestSystemSourceCommit || !slices.Contains(profile.ExcludedIPv4, n.FloorPeerIPv4) {
			return fmt.Errorf("every Native launch must share the qualified network geometry and guest source")
		}
	}
	if used[w.AdapterID] || used[r.AdapterID] {
		return fmt.Errorf("Native floor network cannot reuse provider, pricing or registry instances")
	}
	return nil
}

// PrepareNetwork/ObserveNetwork run outside database locks. This validates a
// complete Source-pinned observation and original stored launch; it does not
// turn host configuration into a Node readiness or useful-capacity receipt.
func NativeWorkerNetworkPreparationValid(p model.CapacityPolicySpec, a model.CapacityNativeWorkerAttempt, launch json.RawMessage, prepared NativeWorkerNetworkPreparation, now time.Time) bool {
	if ValidateNativeWorkerNetworkBinding(p) != nil || p.NativeWorkerLifecycleBinding == nil || p.NativeWorkerLifecycleBinding.Network == nil ||
		a.Physical == nil || !marketSHA.MatchString(a.BirthSHA256) || !reflect.DeepEqual(*a.Physical, prepared.Physical) ||
		prepared.PhysicalObservedAt.IsZero() || prepared.PhysicalObservedAt.After(now) || now.Sub(prepared.PhysicalObservedAt) > time.Duration(p.NativeWorkerLifecycleBinding.MaxReadAgeSeconds)*time.Second || !marketSHA.MatchString(prepared.PhysicalEvidenceSHA256) {
		return false
	}
	b := p.NativeWorkerLifecycleBinding.Network
	providerBound := false
	for _, binding := range p.NativeWorkerLifecycleBinding.PhysicalObservers {
		providerBound = providerBound || binding.Profile == a.Profile && binding.Provider == a.Provider && binding.Region == a.Region && binding.SourceCommit == prepared.PhysicalSourceCommit && binding.ScopeSHA256 == prepared.PhysicalScopeSHA256
	}
	if !providerBound {
		return false
	}
	endpoint, e := netip.ParseAddr(prepared.TransportEndpointIPv4)
	transport, _ := netip.ParsePrefix(b.Template.TransportCIDR)
	if e != nil || !endpoint.Is4() || endpoint.String() != prepared.TransportEndpointIPv4 || !endpoint.IsGlobalUnicast() || endpoint.IsPrivate() || endpoint.IsLoopback() || endpoint.IsLinkLocalUnicast() || transport.Contains(endpoint) {
		return false
	}
	return NativeWorkerNetworkObservationValid(p, a, launch, prepared.Floor, now)
}

// NativeWorkerNetworkPreparationValidForAction keeps installation dependent on
// a fresh independent provider GET. Cleanup instead binds the original sealed
// target and current floor inventory; provider absence must not prevent removal.
// The repository supplies the endpoint from an immutable earlier install grant.
func NativeWorkerNetworkPreparationValidForAction(p model.CapacityPolicySpec, a model.CapacityNativeWorkerAttempt, launch json.RawMessage, prepared NativeWorkerNetworkPreparation, action string, now time.Time) bool {
	if action == "install" {
		return NativeWorkerNetworkPreparationValid(p, a, launch, prepared, now)
	}
	if action != "remove" || a.Physical == nil || !reflect.DeepEqual(*a.Physical, prepared.Physical) || !NativeWorkerNetworkObservationValid(p, a, launch, prepared.Floor, now) {
		return false
	}
	endpoint, err := netip.ParseAddr(prepared.TransportEndpointIPv4)
	return err == nil && endpoint.Is4() && endpoint.String() == prepared.TransportEndpointIPv4 && endpoint.IsGlobalUnicast() && !endpoint.IsPrivate() && !endpoint.IsLoopback() && !endpoint.IsLinkLocalUnicast()
}

// A historical sealed target can receive complete floor readback even after
// provider deletion. This port does not invent a fresh live-provider witness.
func NativeWorkerNetworkObservationValid(p model.CapacityPolicySpec, a model.CapacityNativeWorkerAttempt, launch json.RawMessage, o model.CapacityNativeWorkerNetworkObservation, now time.Time) bool {
	if ValidateNativeWorkerNetworkBinding(p) != nil || p.NativeWorkerLifecycleBinding == nil || p.NativeWorkerLifecycleBinding.Network == nil || a.Physical == nil || !marketSHA.MatchString(a.BirthSHA256) {
		return false
	}
	b, pool := p.NativeWorkerLifecycleBinding.Network, p.NativeWorkerPoolBinding
	var original nativePrivateLaunch
	if nativePrivateSHA(launch) != a.LaunchSHA256 || DecodeNativeCapacity(launch, &original) != nil || original.ReservationID != a.ID.String() || original.PoolUID != a.PoolUID || original.PolicyID != a.PolicyID.String() || original.PolicySHA256 != strings.TrimPrefix(a.PolicyChecksum, "sha256:") || original.IntentGeneration != a.Generation || original.FencingToken != a.FencingToken ||
		original.ExpectedPoolEpoch != a.PoolEpoch || original.Registry.Kind != a.Registry.Kind || original.Registry.Namespace != a.Registry.Namespace || original.Registry.Name != a.Registry.Name || original.Registry.UID != a.Registry.UID ||
		original.SourceCommit != b.Template.GuestSystemSourceCommit || original.Network.TransportCIDR != b.Template.TransportCIDR || original.Network.PodCIDR != b.Template.PodCIDR || original.Network.ServiceCIDR != b.Template.ServiceCIDR || original.Network.WorkerIPv4 != a.OverlayIPv4 || original.Network.FloorPeerIPv4 != b.Template.FloorPeerIPv4 || original.Network.FloorPeerPublicKey != b.Template.FloorPublicKey ||
		original.Floor.NodeUID != b.Floor.NodeUID || original.Floor.NodeName != b.Floor.NodeName || original.Floor.ProviderID != b.Floor.ProviderID || original.Floor.ClusterUID != b.Floor.ClusterUID || original.Floor.CASHA256 != b.Floor.CASHA256 || !nativeWorkerNetworkKey(original.Network.WorkerPublicKey) || original.Network.WorkerPublicKey == b.Template.FloorPublicKey {
		return false
	}
	if o.Schema != model.CapacityNativeWorkerNetworkObservationSchema || o.BindingName != b.Reader.BindingName || o.AdapterSourceCommit != b.Reader.SystemSourceCommit || o.ReaderScopeSHA256 != b.Reader.ScopeSHA256 ||
		o.Requested.BindingName != b.Reader.BindingName || o.Requested.AttemptID != a.ID.String() || o.Requested.LaunchSHA256 != a.LaunchSHA256 || o.Requested.WorkerPublicKey != original.Network.WorkerPublicKey || o.Requested.WorkerIPv4 != a.OverlayIPv4 ||
		o.ObservedAt.IsZero() || o.ObservedAt.After(now) || now.Sub(o.ObservedAt) > time.Duration(p.NativeWorkerLifecycleBinding.MaxReadAgeSeconds)*time.Second ||
		!o.KernelInventoryComplete || !o.Firewall.Complete || o.Floor.Bound != b.Floor || o.Floor.Observed.Hostname != b.Floor.NodeName || o.Floor.Observed.CASHA256 != b.Floor.CASHA256 || o.Floor.Observed.CAOrigin != "source_bound_local_certificate" ||
		o.Floor.Observed.NativeInterfaceIndex < 1 || !o.Floor.Observed.NativeInterfaceUp || !o.Floor.Observed.NativeIPv4Present || o.NetworkTemplateSHA256 != b.TemplateSHA256 || o.MTU != NativeWorkerNetworkMTU || o.KernelSettings.IPForward != 1 ||
		a.PoolUID != pool.PoolUID || a.PoolEpoch != pool.ExpectedPoolEpoch || a.Registry != pool.RegistryRef || a.PolicyChecksum == "" {
		return false
	}
	_, e := o.PreimageSHA256()
	return e == nil
}

// This is only host-side configuration receiving. Even a true install result
// grants no path, DNS, MTU-through-Flannel, Node readiness or admission credit.
func NativeWorkerNetworkDesired(b model.CapacityNativeWorkerNetworkBinding, g model.CapacityNativeWorkerNetworkGrant, o model.CapacityNativeWorkerNetworkObservation) bool {
	if !o.KernelInventoryComplete || !o.Firewall.Complete || o.Peers == nil || o.Routes == nil || o.Firewall.Rules == nil || o.Interface.Addresses == nil ||
		g.NetworkTemplateSHA256 != b.TemplateSHA256 || o.NetworkTemplateSHA256 != b.TemplateSHA256 || o.Firewall.Chain != "inet/dakasa_native/DAKASA_NATIVE" ||
		o.Firewall.RulesSHA256 != nativePrivateSHA([]byte(strings.Join(o.Firewall.Rules, "\n")+"\n")) {
		return false
	}
	worker, e := netip.ParseAddr(g.Peer.WorkerIPv4)
	if e != nil || !worker.Is4() {
		return false
	}
	prefix := netip.PrefixFrom(worker, 32)
	peerCount, routeCount, ruleCount, dropCount := 0, 0, 0, 0
	for _, peer := range o.Peers {
		if peer.PublicKey == g.Peer.WorkerPublicKey {
			peerCount++
			if len(peer.AllowedIPs) != 1 || peer.AllowedIPs[0] != prefix.String() {
				return false
			}
		} else {
			for _, raw := range peer.AllowedIPs {
				allowed, err := netip.ParsePrefix(raw)
				if err != nil || allowed.Contains(worker) {
					return false
				}
			}
		}
	}
	for _, route := range o.Routes {
		if route.Destination != prefix.String() {
			continue
		}
		routeCount++
		if route.Device != b.Template.Interface || route.PreferredSource != b.Floor.NativeIPv4 {
			return false
		}
	}
	for _, rule := range o.Firewall.Rules {
		if rule == "dakasa-native:drop" {
			dropCount++
			continue
		}
		if strings.HasPrefix(rule, "dakasa-native:"+g.AttemptID+"|") {
			ruleCount++
			if rule != "dakasa-native:"+g.AttemptID+"|"+g.Peer.TransportEndpointIPv4 {
				return false
			}
		}
	}
	if g.Action == "remove" {
		return peerCount == 0 && routeCount == 0 && ruleCount == 0
	}
	if g.Action != "install" || peerCount != 1 || routeCount != 1 || ruleCount != 1 || dropCount != 1 || !o.Interface.Present || !o.Interface.Up || o.Interface.Name != b.Template.Interface || o.Interface.IfIndex < 1 || o.Interface.MTU != NativeWorkerNetworkMTU ||
		o.Interface.PublicKey != b.Template.FloorPublicKey || o.Interface.ListenPort != b.Template.ListenPort || !slices.Contains(o.Interface.Addresses, b.Template.FloorPeerIPv4+"/32") || o.KernelSettings.IPForward != 1 || !o.KernelSettings.WireGuardRPFilterObserved {
		return false
	}
	// Strict reverse-path filtering would reject a correctly routed asymmetric
	// overlay packet. Observed disabled/loose modes are facts, not a sysctl write.
	for _, value := range []int{o.KernelSettings.AllRPFilter, o.KernelSettings.NativeRPFilter, o.KernelSettings.WireGuardRPFilter} {
		if value < 0 || value > 2 {
			return false
		}
	}
	return max(o.KernelSettings.AllRPFilter, o.KernelSettings.WireGuardRPFilter) != 1
}
