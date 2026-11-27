package capacity

import (
	"bytes"
	"encoding/base64"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
)

// Mirrors only System's public Launch/Binding validation. It reads no local
// material and grants no bootstrap, network, registration or admission right.
func validateNativePhysicalSystemContext(l nativePrivateLaunch) error {
	name := regexp.MustCompile(`^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$`)
	if l.Schema != 1 || l.Mode != "native_k3s_worker_v1" || !marketCommit.MatchString(l.SourceCommit) || !name.MatchString(l.PoolID) || len(l.PoolID) > 40 || !marketUUID.MatchString(l.PoolUID) || l.Registry.Kind != "Lease" || !name.MatchString(l.Registry.Namespace) || len(l.Registry.Namespace) > 63 || !name.MatchString(l.Registry.Name) || len(l.Registry.Name) > 63 || !marketUUID.MatchString(l.Registry.UID) || !marketUUID.MatchString(l.PolicyID) || !marketSHA.MatchString(l.PolicySHA256) || l.ExpectedPoolEpoch < 1 || l.IntentGeneration < 1 || l.FencingToken < 1 || !marketUUID.MatchString(l.ReservationID) || !marketSHA.MatchString(l.IntentSHA256) || l.Operator.SourceCommit != l.SourceCommit || !marketSHA.MatchString(l.Operator.SHA256) || l.Operator.Bytes < 1 || l.Operator.Bytes > 512<<20 || l.Operator.CapabilityRef != "native-private://operator-capability" || !regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]\.s3\.us-east-1\.amazonaws\.com$`).MatchString(l.Operator.ExpectedHostname) {
		return errNativePhysical
	}
	f, n := l.Floor, l.Network
	if !name.MatchString(f.NodeName) || len(f.NodeName) > 63 || !marketUUID.MatchString(f.NodeUID) || !marketUUID.MatchString(f.ClusterUID) || !regexp.MustCompile(`^hcloud://[1-9][0-9]{0,11}$`).MatchString(f.ProviderID) || !marketSHA.MatchString(f.CASHA256) {
		return errNativePhysical
	}
	u, e := url.Parse(f.APIEndpoint)
	if e != nil || u.Scheme != "https" || u.User != nil || u.Port() != "6443" || u.RawQuery != "" || u.Fragment != "" || u.Path != "" || u.Opaque != "" {
		return errNativePhysical
	}
	api, ok := nativePhysicalPrivateIP(u.Hostname())
	if !ok {
		return errNativePhysical
	}
	if n.Mode != "wireguard_routed_v1" || !nativePhysicalPublicKey(n.FloorPeerPublicKey) || !nativePhysicalPublicKey(n.WorkerPublicKey) || n.FloorPeerPublicKey == n.WorkerPublicKey {
		return errNativePhysical
	}
	transport, ok := nativePhysicalPrivatePrefix(n.TransportCIDR)
	if !ok || transport.Bits() < 16 {
		return errNativePhysical
	}
	floor, ok := nativePhysicalPrivatePrefix(f.NodeNetworkCIDR)
	if !ok || !floor.Contains(api) {
		return errNativePhysical
	}
	pod, ok := nativePhysicalPrivatePrefix(n.PodCIDR)
	if !ok {
		return errNativePhysical
	}
	service, ok := nativePhysicalPrivatePrefix(n.ServiceCIDR)
	if !ok {
		return errNativePhysical
	}
	native, ok := nativePhysicalPrivatePrefix(l.Provider.NativeNetworkCIDR)
	if !ok {
		return errNativePhysical
	}
	prefixes := []netip.Prefix{transport, floor, pod, service, native}
	for i, a := range prefixes {
		for j, b := range prefixes {
			if i < j && a.Overlaps(b) {
				return errNativePhysical
			}
		}
	}
	worker, ok := nativePhysicalPrivateIP(n.WorkerIPv4)
	if !ok || !transport.Contains(worker) {
		return errNativePhysical
	}
	peer, ok := nativePhysicalPrivateIP(n.FloorPeerIPv4)
	if !ok || !transport.Contains(peer) || peer == worker || peer == transport.Addr() || worker == transport.Addr() || worker == api {
		return errNativePhysical
	}
	host, port, e := net.SplitHostPort(n.FloorPeerEndpoint)
	if e != nil {
		return errNativePhysical
	}
	endpoint, e := netip.ParseAddr(host)
	number, e2 := strconv.Atoi(port)
	if e != nil || e2 != nil || !endpoint.Is4() || !endpoint.IsGlobalUnicast() || endpoint.IsPrivate() || endpoint.IsLoopback() || endpoint.String() != host || number < 1024 || number > 65535 || strconv.Itoa(number) != port {
		return errNativePhysical
	}
	r := l.Reserve
	if r.KubeMilliCPU < 1 || r.KubeMilliCPU > 1000 || r.SystemMilliCPU < 1 || r.SystemMilliCPU > 1000 || r.KubeMemoryMiB < 1 || r.KubeMemoryMiB > 1024 || r.SystemMemoryMiB < 1 || r.SystemMemoryMiB > 1024 || r.EvictionMemoryMiB < 1 || r.EvictionMemoryMiB > 1024 {
		return errNativePhysical
	}
	return nil
}
func nativePhysicalPrivateIP(raw string) (netip.Addr, bool) {
	a, e := netip.ParseAddr(raw)
	return a, e == nil && a.Is4() && a.IsPrivate() && a.String() == raw
}
func nativePhysicalPrivatePrefix(raw string) (netip.Prefix, bool) {
	p, e := netip.ParsePrefix(raw)
	return p, e == nil && p.Addr().Is4() && p.Addr().IsPrivate() && p == p.Masked() && p.String() == raw && p.Bits() >= 8 && p.Bits() <= 30
}
func nativePhysicalPublicKey(raw string) bool {
	b, e := base64.StdEncoding.DecodeString(raw)
	return e == nil && len(b) == 32 && base64.StdEncoding.EncodeToString(b) == raw && !bytes.Equal(b, make([]byte, 32))
}
