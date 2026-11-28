package capacity

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

var errNativeWorkerNetworkRPC = errors.New("HOLD: protected floor network RPC or original return is unqualified")
var nativeFloorRPCName = regexp.MustCompile(`^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$`)
var nativeFloorRPCProviderID = regexp.MustCompile(`^hcloud://[1-9][0-9]{0,11}$`)

// This Go-only configuration is installed by protected process composition.
// URLs, files, roles and trust pins are never selected by manifests or RPCs.
// ScopeSHA256 is the SHA256 of the whole reviewed System binding file, not a
// re-encoding of one binding or a peer-selected scope echo.
type NativeWorkerNetworkRPCConfig struct {
	Role                    string
	AdapterID               string
	BindingName             string
	SystemSourceCommit      string
	ScopeSHA256             string
	Floor                   model.CapacityNativeWorkerNetworkFloorIdentity
	Template                model.CapacityNativeWorkerNetworkTemplate
	TemplateSHA256          string
	MaxReadAgeSeconds       int
	ServerCAFile            string
	ServerCASHA256          string
	ServerCertificateSHA256 string
	ClientCertificateFile   string
	ClientKeyFile           string
}

// Mutation results mirror System's actual five fields. They are an original
// RPC disposition, never a host-effect, network-qualification or admission
// receipt. Core's independent receiving remains responsible for those facts.
type NativeWorkerNetworkRPCMutationResult struct {
	PermitID           string `json:"permit_id"`
	State              string `json:"state"`
	GetOnlyRecovery    bool   `json:"get_only_recovery"`
	NetworkQualified   bool   `json:"network_qualified"`
	SchedulingAdmitted bool   `json:"scheduling_admitted"`
}

// Copies share an opaque, idempotent Close fence, including active HTTP reads.
type NativeWorkerNetworkRPCClient struct{ *nativeWorkerNetworkRPCState }

type nativeWorkerNetworkRPCState struct {
	mu     sync.RWMutex
	closed bool
	config NativeWorkerNetworkRPCConfig
	target string
	client *http.Client
	leaf   *x509.Certificate
}

func (NativeWorkerNetworkRPCClient) String() string     { return "[private floor network RPC client]" }
func (c NativeWorkerNetworkRPCClient) GoString() string { return c.String() }
func (NativeWorkerNetworkRPCClient) MarshalJSON() ([]byte, error) {
	return []byte(`{"private_floor_network_rpc":"redacted"}`), nil
}

func nativeWorkerNetworkRPCConfigValid(c NativeWorkerNetworkRPCConfig) bool {
	f, n := c.Floor, c.Template
	native, err := netip.ParseAddr(f.NativeIPv4)
	transport, transportOK := nativeWorkerNetworkPrefix(n.TransportCIDR)
	pods, podsOK := nativeWorkerNetworkPrefix(n.PodCIDR)
	services, servicesOK := nativeWorkerNetworkPrefix(n.ServiceCIDR)
	floor, floorErr := netip.ParseAddr(n.FloorPeerIPv4)
	dns, dnsErr := netip.ParseAddr(n.ClusterDNSIPv4)
	return (c.Role == "reader" || c.Role == "writer") && marketUUID.MatchString(c.AdapterID) && nativeFloorRPCName.MatchString(c.BindingName) && len(c.BindingName) <= 63 &&
		marketCommit.MatchString(c.SystemSourceCommit) && marketSHA.MatchString(c.ScopeSHA256) && c.MaxReadAgeSeconds >= 1 && c.MaxReadAgeSeconds <= 120 &&
		marketSHA.MatchString(c.ServerCASHA256) && marketSHA.MatchString(c.ServerCertificateSHA256) &&
		nativeFloorRPCName.MatchString(f.NodeName) && len(f.NodeName) <= 63 && marketUUID.MatchString(f.NodeUID) && marketUUID.MatchString(f.ClusterUID) &&
		nativeFloorRPCProviderID.MatchString(f.ProviderID) && marketSHA.MatchString(f.CASHA256) && f.NativeInterface == "enp7s0" &&
		err == nil && native.Is4() && native.IsPrivate() && native.String() == f.NativeIPv4 &&
		n.Schema == 1 && n.GuestSystemSourceCommit == c.SystemSourceCommit && n.Interface == "wg-dakasa" && n.MTU == NativeWorkerNetworkMTU &&
		transportOK && transport.Bits() >= 16 && podsOK && servicesOK && !transport.Overlaps(pods) && !transport.Overlaps(services) && !pods.Overlaps(services) &&
		!transport.Contains(native) && !pods.Contains(native) && !services.Contains(native) &&
		floorErr == nil && floor.Is4() && floor.String() == n.FloorPeerIPv4 && transport.Contains(floor) && floor != transport.Addr() &&
		dnsErr == nil && dns.Is4() && dns.String() == n.ClusterDNSIPv4 && services.Contains(dns) && dns != services.Addr() &&
		nativeWorkerNetworkKey(n.FloorPublicKey) && n.ListenPort >= 1024 && n.ListenPort <= 65535 && n.FirewallChain == "DAKASA_NATIVE" &&
		n.DNSName == "kubernetes.default.svc.cluster.local" && marketSHA.MatchString(c.TemplateSHA256) && NativeWorkerNetworkTemplateSHA256(n) == c.TemplateSHA256
}

func NewNativeWorkerNetworkRPCClient(c NativeWorkerNetworkRPCConfig) (*NativeWorkerNetworkRPCClient, error) {
	return newNativeWorkerNetworkRPCClient(c, nil)
}

// The private dialer seam is used only by in-package CI to reach an isolated
// loopback socket. The actual request URL, Host, IP SAN and leaf verification
// remain the configured floor address and fixed role port; production exposes
// no URL, transport, header, environment or dialer override.
func newNativeWorkerNetworkRPCClient(c NativeWorkerNetworkRPCConfig, dial func(context.Context, string, string) (net.Conn, error)) (*NativeWorkerNetworkRPCClient, error) {
	if !nativeWorkerNetworkRPCConfigValid(c) {
		return nil, errNativeWorkerNetworkRPC
	}
	ca, err := nativePrivateReadFile(c.ServerCAFile, 65536, false)
	if err != nil || nativeRPCHash(ca) != c.ServerCASHA256 {
		return nil, errNativeWorkerNetworkRPC
	}
	pool, err := nativeRPCCAPool(ca)
	if err != nil {
		return nil, errNativeWorkerNetworkRPC
	}
	cert, err := nativePrivateReadFile(c.ClientCertificateFile, 65536, false)
	if err != nil {
		return nil, errNativeWorkerNetworkRPC
	}
	remaining, count := cert, 0
	for len(bytes.TrimSpace(remaining)) > 0 {
		if !bytes.HasPrefix(bytes.TrimSpace(remaining), []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, errNativeWorkerNetworkRPC
		}
		block, rest := pem.Decode(remaining)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, errNativeWorkerNetworkRPC
		}
		if _, err = x509.ParseCertificate(block.Bytes); err != nil {
			return nil, errNativeWorkerNetworkRPC
		}
		count++
		remaining = rest
	}
	if count < 1 || count > 8 {
		return nil, errNativeWorkerNetworkRPC
	}
	key, err := nativePrivateReadFile(c.ClientKeyFile, 32768, true)
	if err != nil {
		return nil, errNativeWorkerNetworkRPC
	}
	defer nativePrivateWipe(key)
	pair, err := tls.X509KeyPair(cert, key)
	if err != nil || len(pair.Certificate) < 1 || len(pair.Certificate) > 8 {
		return nil, errNativeWorkerNetworkRPC
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil || !nativeRPCLeaf(leaf, x509.ExtKeyUsageClientAuth) {
		return nil, errNativeWorkerNetworkRPC
	}
	pair.Leaf = leaf
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool, Certificates: []tls.Certificate{pair},
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.VerifiedChains) < 1 || len(state.PeerCertificates) < 1 || nativeRPCHash(state.PeerCertificates[0].Raw) != c.ServerCertificateSHA256 || !nativeRPCLeaf(state.PeerCertificates[0], x509.ExtKeyUsageServerAuth) {
				return errNativeWorkerNetworkRPC
			}
			return nil
		}}
	transport := nativeRPCTransport(tlsConfig)
	if dial != nil {
		transport.DialContext = dial
	}
	port := "9444"
	if c.Role == "writer" {
		port = "9443"
	}
	return &NativeWorkerNetworkRPCClient{&nativeWorkerNetworkRPCState{config: c, leaf: leaf,
		target: "https://" + net.JoinHostPort(c.Floor.NativeIPv4, port) + "/rpc/execute",
		client: &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return errNativeWorkerNetworkRPC }}}}, nil
}

// Matches binds the whole protected file scope and the exact Source-owned
// policy declarations. It does not assert that a host mutation took effect.
func (c *NativeWorkerNetworkRPCClient) Matches(role string, b model.CapacityNativeWorkerNetworkBinding) bool {
	if c == nil || c.nativeWorkerNetworkRPCState == nil {
		return false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.closed || role != c.config.Role || b.Mode != NativeWorkerNetworkMode || b.Floor != c.config.Floor || b.Template != c.config.Template || b.TemplateSHA256 != c.config.TemplateSHA256 {
		return false
	}
	if role == "reader" {
		return b.Reader.AdapterID == c.config.AdapterID && b.Reader.BindingName == c.config.BindingName && b.Reader.SystemSourceCommit == c.config.SystemSourceCommit && b.Reader.ScopeSHA256 == c.config.ScopeSHA256
	}
	return role == "writer" && b.Writer.AdapterID == c.config.AdapterID && b.Writer.BindingName == c.config.BindingName && b.Writer.SystemSourceCommit == c.config.SystemSourceCommit && b.Writer.ScopeSHA256 == c.config.ScopeSHA256
}

func (c *NativeWorkerNetworkRPCClient) Observe(ctx context.Context, in model.CapacityNativeWorkerNetworkObserveInput) (model.CapacityNativeWorkerNetworkObservation, error) {
	var out model.CapacityNativeWorkerNetworkObservation
	if c == nil || c.nativeWorkerNetworkRPCState == nil || !nativeRPCDeadline(ctx) {
		return out, errNativeWorkerNetworkRPC
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.closed || c.config.Role != "reader" || !c.selectorValid(in) {
		return out, errNativeWorkerNetworkRPC
	}
	raw, err := c.call(ctx, ObserveNativeWorkerNetwork, in)
	if err != nil || nativeWorkerNetworkRPCDecode(raw, &out) != nil {
		return model.CapacityNativeWorkerNetworkObservation{}, errNativeWorkerNetworkRPC
	}
	now := time.Now().UTC()
	f := out.Floor.Observed
	if out.Schema != model.CapacityNativeWorkerNetworkObservationSchema || out.BindingName != c.config.BindingName || out.AdapterSourceCommit != c.config.SystemSourceCommit || out.ReaderScopeSHA256 != c.config.ScopeSHA256 ||
		out.Requested != in || out.Floor.Bound != c.config.Floor || f.Hostname != c.config.Floor.NodeName || f.CASHA256 != c.config.Floor.CASHA256 || f.CAOrigin != "source_bound_local_certificate" || f.NativeInterfaceIndex < 1 || !f.NativeInterfaceUp || !f.NativeIPv4Present ||
		out.NetworkTemplateSHA256 != c.config.TemplateSHA256 || out.MTU != c.config.Template.MTU || out.Interface.Name != c.config.Template.Interface || out.ObservedAt.IsZero() || out.ObservedAt.After(now) || now.Sub(out.ObservedAt) > time.Duration(c.config.MaxReadAgeSeconds)*time.Second ||
		out.Firewall.Chain != "inet/dakasa_native/"+c.config.Template.FirewallChain || out.Firewall.RulesSHA256 != nativePrivateSHA([]byte(strings.Join(out.Firewall.Rules, "\n")+"\n")) {
		return model.CapacityNativeWorkerNetworkObservation{}, errNativeWorkerNetworkRPC
	}
	if _, err = out.PreimageSHA256(); err != nil {
		return model.CapacityNativeWorkerNetworkObservation{}, errNativeWorkerNetworkRPC
	}
	return out, nil
}

func (c *NativeWorkerNetworkRPCClient) selectorValid(in model.CapacityNativeWorkerNetworkObserveInput) bool {
	ip, err := netip.ParseAddr(in.WorkerIPv4)
	prefix, _ := netip.ParsePrefix(c.config.Template.TransportCIDR)
	return in.BindingName == c.config.BindingName && marketUUID.MatchString(in.AttemptID) && marketSHA.MatchString(in.LaunchSHA256) && nativeWorkerNetworkKey(in.WorkerPublicKey) && in.WorkerPublicKey != c.config.Template.FloorPublicKey &&
		err == nil && ip.Is4() && ip.String() == in.WorkerIPv4 && prefix.Contains(ip) && ip != prefix.Addr() && in.WorkerIPv4 != c.config.Template.FloorPeerIPv4
}

func (c *NativeWorkerNetworkRPCClient) Mutate(ctx context.Context, operation string, in model.CapacityNativeWorkerNetworkMutationInput) (NativeWorkerNetworkRPCMutationResult, error) {
	var out NativeWorkerNetworkRPCMutationResult
	if c == nil || c.nativeWorkerNetworkRPCState == nil || !nativeRPCDeadline(ctx) {
		return out, errNativeWorkerNetworkRPC
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.closed || c.config.Role != "writer" || (operation != NativeWorkerNetworkInstall && operation != NativeWorkerNetworkRemove) || in.BindingName != c.config.BindingName || !marketUUID.MatchString(in.PermitID) {
		return out, errNativeWorkerNetworkRPC
	}
	raw, err := c.call(ctx, operation, in)
	if err != nil || nativeWorkerNetworkRPCDecode(raw, &out) != nil || out.PermitID != in.PermitID || !out.GetOnlyRecovery || out.NetworkQualified || out.SchedulingAdmitted {
		return NativeWorkerNetworkRPCMutationResult{}, errNativeWorkerNetworkRPC
	}
	switch out.State {
	case "issued", "redeemed", "received", "unknown", "no_effect", "observed", "original_return_custodied":
		return out, nil
	default:
		return NativeWorkerNetworkRPCMutationResult{}, errNativeWorkerNetworkRPC
	}
}

// Every output field in these closed System DTOs is required, including false
// booleans and empty arrays. A typed roundtrip checks presence/null at every
// depth without treating missing observations as actual empty inventories.
func nativeWorkerNetworkRPCDecode(raw []byte, out any) error {
	if DecodeNativeCapacity(json.RawMessage(raw), out) != nil {
		return errNativeWorkerNetworkRPC
	}
	canonical, err := json.Marshal(out)
	var actual, typed any
	if err != nil || json.Unmarshal(raw, &actual) != nil || json.Unmarshal(canonical, &typed) != nil || !reflect.DeepEqual(actual, typed) {
		return errNativeWorkerNetworkRPC
	}
	return nil
}

func (c *NativeWorkerNetworkRPCClient) call(ctx context.Context, operation string, input any) ([]byte, error) {
	if !nativeRPCLeaf(c.leaf, x509.ExtKeyUsageClientAuth) {
		return nil, errNativeWorkerNetworkRPC
	}
	requestBody, err := json.Marshal(struct {
		Operation  string `json:"operation"`
		Capability string `json:"capability"`
		Input      any    `json:"input"`
	}{operation, operation, input})
	if err != nil || len(requestBody) > 64<<10 {
		return nil, errNativeWorkerNetworkRPC
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.target, bytes.NewReader(requestBody))
	if err != nil {
		return nil, errNativeWorkerNetworkRPC
	}
	request.GetBody = nil
	request.Header.Set("Content-Type", "application/json")
	reply, callErr := c.client.Do(request)
	var raw []byte
	var readErr, closeErr error
	valid := callErr == nil && reply != nil && reply.Body != nil && reply.StatusCode == http.StatusOK && reply.Request != nil && reply.Request.URL != nil && reply.Request.URL.String() == c.target && reply.Request.Method == http.MethodPost && reply.TLS != nil && len(reply.TLS.VerifiedChains) > 0
	if valid {
		sources := reply.Header.Values("X-Yggdrasil-Source-Commit")
		valid = len(sources) == 1 && sources[0] == c.config.SystemSourceCommit && reply.Header.Get("Content-Type") == "application/json"
	}
	if reply != nil && reply.Body != nil {
		if valid {
			raw, readErr = io.ReadAll(io.LimitReader(reply.Body, (2<<20)+1))
		}
		closeErr = reply.Body.Close()
	}
	if !valid || errors.Join(callErr, readErr, closeErr, ctx.Err()) != nil || !nativeRPCDeadline(ctx) || len(raw) > 2<<20 {
		return nil, errNativeWorkerNetworkRPC
	}
	var envelope struct {
		Operation  string          `json:"operation"`
		Capability string          `json:"capability"`
		Status     string          `json:"status"`
		Output     json.RawMessage `json:"output"`
		Metadata   struct {
			NetworkAdmissionQualified bool `json:"network_admission_qualified"`
			UsefulCapacityQualified   bool `json:"useful_capacity_qualified"`
		} `json:"metadata"`
	}
	// RawMessage output is decoded against its complete concrete DTO by the
	// role-specific method; the envelope and metadata have no optional fields.
	if nativeWorkerNetworkRPCDecode(raw, &envelope) != nil || envelope.Operation != operation || envelope.Capability != operation || envelope.Status != "observed" || envelope.Metadata.NetworkAdmissionQualified || envelope.Metadata.UsefulCapacityQualified || bytes.Equal(bytes.TrimSpace(envelope.Output), []byte("null")) {
		return nil, errNativeWorkerNetworkRPC
	}
	return envelope.Output, nil
}

func (c *NativeWorkerNetworkRPCClient) Close() error {
	if c == nil || c.nativeWorkerNetworkRPCState == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	c.client.CloseIdleConnections()
	c.client, c.leaf = nil, nil
	return nil
}
