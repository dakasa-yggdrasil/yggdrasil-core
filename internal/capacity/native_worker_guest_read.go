package capacity

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// GuestWitnessProofFunc is a protected process composition port, not a machine
// request, workflow field or certificate permission. A complete independent
// network/path/warmup producer must supply the actual readiness proof. Merely
// authenticating this local witness never supplies those missing facts.
type NativeWorkerGuestWitnessProofFunc func(context.Context, model.CapacityNativeWorkerAttempt, model.CapacityNativeWorkerGuestWitness) (*model.CapacityNativeWorkerReadinessProof, error)

func nativeGuestTemplateMatches(n model.CapacityNativeWorkerNetworkTemplate, l nativePrivateLaunch) bool {
	_, port, err := net.SplitHostPort(l.Network.FloorPeerEndpoint)
	dns, de := netip.ParseAddr(n.ClusterDNSIPv4)
	service, se := netip.ParsePrefix(n.ServiceCIDR)
	return n.Schema == 1 && n.GuestSystemSourceCommit == l.SourceCommit && n.Interface == "wg-dakasa" && n.MTU == NativeWorkerNetworkMTU && n.TransportCIDR == l.Network.TransportCIDR && n.FloorPeerIPv4 == l.Network.FloorPeerIPv4 && n.FloorPublicKey == l.Network.FloorPeerPublicKey && n.PodCIDR == l.Network.PodCIDR && n.ServiceCIDR == l.Network.ServiceCIDR && err == nil && port == fmtGuestPort(n.ListenPort) && n.FirewallChain == "DAKASA_NATIVE" && de == nil && dns.Is4() && dns.String() == n.ClusterDNSIPv4 && se == nil && service.Contains(dns) && n.DNSName == "kubernetes.default.svc.cluster.local"
}

func fmtGuestPort(port int) string {
	if port < 1024 || port > 65535 {
		return ""
	}
	return strconv.Itoa(port)
}

func nativeGuestWitnessValid(g *nativeGuestReadIdentity, a model.CapacityNativeWorkerAttempt, l nativePrivateLaunch, o model.CapacityNativeWorkerGuestWitness, now time.Time) bool {
	if g == nil || a.Physical == nil || !NativeWorkerPhysicalValid(a, *a.Physical) || !marketSHA.MatchString(a.BirthSHA256) || o.Schema != "native_worker_guest_network_witness_v1" || o.SystemSourceCommit != l.SourceCommit || o.AttemptID != a.ID.String() || o.LaunchSHA256 != a.LaunchSHA256 || o.BindingSHA256 != a.Physical.PhysicalBindingSHA256 || o.NetworkTemplateSHA256 != g.config.NetworkTemplateSHA256 || o.ObservedAt.IsZero() || o.ObservedAt.After(now) || now.Sub(o.ObservedAt) > time.Duration(g.config.MaxReadAgeSeconds)*time.Second || !nativeGuestTemplateMatches(g.network, l) || o.InterfaceName != g.network.Interface || o.InterfaceIndex < 1 || o.MTU != g.network.MTU || !o.InterfaceUp || !o.WorkerIPv4Present || o.WireGuardPublicKey != l.Network.WorkerPublicKey || o.FloorPeerPublicKey != l.Network.FloorPeerPublicKey || o.FloorPeerEndpoint != l.Network.FloorPeerEndpoint || o.FloorPeerLastHandshakeUnix <= 0 || time.Unix(o.FloorPeerLastHandshakeUnix, 0).After(o.ObservedAt) || o.ObservedAt.Sub(time.Unix(o.FloorPeerLastHandshakeUnix, 0)) > 180*time.Second || !o.FloorTLSVerified || o.EndToEndPathMTUQualified || o.IndependentNetworkQualified || o.SchedulingAdmitted || o.UsefulCapacityQualified || o.DNSName != g.network.DNSName || o.DNSResolverIPv4 != g.network.ClusterDNSIPv4 || len(o.DNSAnswerIPv4) < 1 || len(o.DNSAnswerIPv4) > 16 || len(o.Routes) != 2+len(o.DNSAnswerIPv4) {
		return false
	}
	api, err := url.Parse(l.Floor.APIEndpoint)
	if err != nil {
		return false
	}
	services, _ := netip.ParsePrefix(g.network.ServiceCIDR)
	targets := map[string]int{api.Hostname(): 1}
	targets[g.network.ClusterDNSIPv4]++
	seen := map[string]bool{}
	for _, raw := range o.DNSAnswerIPv4 {
		ip, e := netip.ParseAddr(raw)
		if e != nil || !ip.Is4() || ip.String() != raw || !services.Contains(ip) || seen[raw] {
			return false
		}
		seen[raw] = true
		targets[raw]++
	}
	for _, r := range o.Routes {
		if r.Device != g.network.Interface || r.SourceIPv4 != a.OverlayIPv4 || targets[r.TargetIPv4] < 1 {
			return false
		}
		targets[r.TargetIPv4]--
	}
	for _, left := range targets {
		if left != 0 {
			return false
		}
	}
	return true
}

// This per-call client has no shared idle connection and no caller-selected
// destination. A fresh transport performs one fixed GET, with normal hostname
// validation plus the exact deterministic Attempt/Launch leaf and URI pin.
func (g *nativeGuestReadIdentity) read(ctx context.Context, a model.CapacityNativeWorkerAttempt, launch []byte, source string, dial func(context.Context, string, string) (net.Conn, error)) (model.CapacityNativeWorkerGuestWitness, error) {
	var zero model.CapacityNativeWorkerGuestWitness
	if !nativeRPCDeadline(ctx) {
		return zero, errNativeGuestRead
	}
	cert, err := g.derive(a, launch, source)
	if err != nil {
		return zero, errNativeGuestRead
	}
	defer cert.close()
	clientCert, err := g.deriveClient(a, launch, source)
	if err != nil {
		return zero, errNativeGuestRead
	}
	defer clientCert.close()
	pair, err := tls.X509KeyPair(clientCert.certificatePEM, clientCert.privateKeyPEM)
	if err != nil {
		return zero, errNativeGuestRead
	}
	clientKey, ok := pair.PrivateKey.(ed25519.PrivateKey)
	if !ok {
		return zero, errNativeGuestRead
	}
	defer nativePrivateWipe(clientKey)
	now := time.Now().UTC()
	if !now.Before(cert.notAfter) {
		return zero, errNativeGuestRead
	}
	pool := x509.NewCertPool()
	pool.AddCert(g.issuer)
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool, Certificates: []tls.Certificate{pair}, VerifyConnection: func(s tls.ConnectionState) error {
		if len(s.VerifiedChains) < 1 || len(s.PeerCertificates) < 1 || nativePrivateSHA(s.PeerCertificates[0].Raw) != cert.fingerprint || !nativeRPCLeaf(s.PeerCertificates[0], x509.ExtKeyUsageServerAuth) || len(s.PeerCertificates[0].URIs) != 1 || s.PeerCertificates[0].URIs[0].String() != cert.uri {
			return errNativeGuestRead
		}
		return nil
	}}
	transport := nativeRPCTransport(tlsConfig)
	transport.DisableKeepAlives = true
	if dial != nil {
		transport.DialContext = dial
	}
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return errNativeGuestRead }}
	defer client.CloseIdleConnections()
	target := "https://" + net.JoinHostPort(a.OverlayIPv4, nativeWorkerGuestWitnessPort) + NativeWorkerGuestWitnessPath
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return zero, errNativeGuestRead
	}
	request.GetBody = nil
	response, callErr := client.Do(request)
	raw, err := nativeGuestOriginalRead(ctx, response, callErr, target, source)
	if err != nil {
		return zero, errNativeGuestRead
	}
	var out model.CapacityNativeWorkerGuestWitness
	var l nativePrivateLaunch
	if nativeWorkerNetworkRPCDecode(raw, &out) != nil || DecodeNativeCapacity(json.RawMessage(launch), &l) != nil || !nativeGuestWitnessValid(g, a, l, out, time.Now().UTC()) {
		return zero, errNativeGuestRead
	}
	// The DTO owns slices independent of any transport buffer or reusable value.
	out.Routes = slices.Clone(out.Routes)
	out.DNSAnswerIPv4 = slices.Clone(out.DNSAnswerIPv4)
	return out, nil
}

// Consume only the authenticated original return, including its actual Close.
func nativeGuestOriginalRead(ctx context.Context, response *http.Response, callErr error, target, source string) ([]byte, error) {
	valid := nativeRPCDeadline(ctx) && callErr == nil && response != nil && response.Body != nil && response.StatusCode == http.StatusOK && response.Request != nil && response.Request.URL != nil && response.Request.URL.String() == target && response.Request.Method == http.MethodGet && response.TLS != nil && len(response.TLS.VerifiedChains) > 0
	if valid {
		sourceHeaders := response.Header.Values("X-Yggdrasil-Source-Commit")
		valid = len(sourceHeaders) == 1 && sourceHeaders[0] == source && response.Header.Get("Content-Type") == "application/json"
	}
	var raw []byte
	var readErr, closeErr error
	if response != nil && response.Body != nil {
		if valid {
			raw, readErr = io.ReadAll(io.LimitReader(response.Body, (64<<10)+1))
		}
		closeErr = response.Body.Close()
	}
	if !valid || errors.Join(callErr, readErr, closeErr, ctx.Err()) != nil || !nativeRPCDeadline(ctx) || len(raw) > 64<<10 {
		return nil, errNativeGuestRead
	}
	return raw, nil
}
