package capacity

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

var errNativeWorkerRPC = errors.New("HOLD: protected Native RPC binding or original return is unqualified")

// Only protected process composition constructs this configuration. Its TLS
// material is read from protected files, never from manifests or RPC inputs.
type NativeWorkerRPCConfig struct {
	Adapter                 model.CapacityMarketAdapterBinding
	Profile                 string
	BindingName             string
	SDKSourceCommit         string
	ScopeSHA256             string
	BaseURL                 string
	HealthURL               string
	ServerCAFile            string
	ServerCASHA256          string
	ServerCertificateSHA256 string
	ClientCertificateFile   string
	ClientKeyFile           string
	AllowedCapabilities     []string
}

// All copies share one Close fence. Representations never traverse TLS keys.
type NativeWorkerRPCClient struct{ *nativeWorkerRPCState }

type nativeWorkerRPCState struct {
	mu        sync.RWMutex
	closed    bool
	config    NativeWorkerRPCConfig
	tlsClient *http.Client
	health    *http.Client
	leaf      *x509.Certificate
	allowed   map[string]bool
}

func (NativeWorkerRPCClient) String() string     { return "[private Native RPC client]" }
func (c NativeWorkerRPCClient) GoString() string { return c.String() }
func (NativeWorkerRPCClient) MarshalJSON() ([]byte, error) {
	return []byte(`{"private_native_rpc":"redacted"}`), nil
}

func nativeRPCHash(raw []byte) string { s := sha256.Sum256(raw); return hex.EncodeToString(s[:]) }

func nativeRPCURL(raw string, tlsOnly bool) bool {
	u, e := url.Parse(raw)
	return e == nil && u.Host != "" && u.User == nil && u.RawQuery == "" && u.Fragment == "" && u.RawPath == "" &&
		(u.Scheme == "https" || !tlsOnly && u.Scheme == "http") && !strings.HasSuffix(u.Host, ":") && u.String() == raw
}

func nativeRPCLeaf(leaf *x509.Certificate, usage x509.ExtKeyUsage) bool {
	if leaf == nil || leaf.IsCA || time.Now().Before(leaf.NotBefore) || !time.Now().Before(leaf.NotAfter) || leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return false
	}
	for _, u := range leaf.ExtKeyUsage {
		if u == usage {
			return true
		}
	}
	return false
}

func nativeRPCCAPool(raw []byte) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	count := 0
	for len(bytes.TrimSpace(raw)) > 0 {
		if !bytes.HasPrefix(bytes.TrimSpace(raw), []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, errNativeWorkerRPC
		}
		block, rest := pem.Decode(raw)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, errNativeWorkerRPC
		}
		cert, e := x509.ParseCertificate(block.Bytes)
		if e != nil || !cert.IsCA || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
			return nil, errNativeWorkerRPC
		}
		pool.AddCert(cert)
		count++
		raw = rest
	}
	if count < 1 || count > 8 {
		return nil, errNativeWorkerRPC
	}
	return pool, nil
}

func nativeRPCTransport(config *tls.Config) *http.Transport {
	return &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		TLSClientConfig: config, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 15 * time.Second,
		DisableKeepAlives: true, MaxResponseHeaderBytes: 32 << 10}
}

func NewNativeWorkerRPCClient(c NativeWorkerRPCConfig) (*NativeWorkerRPCClient, error) {
	u, e := url.Parse(c.BaseURL)
	if e != nil || !marketAdapterValid(c.Adapter) || !marketID.MatchString(c.Profile) || !marketID.MatchString(c.BindingName) ||
		!marketCommit.MatchString(c.SDKSourceCommit) || !marketSHA.MatchString(c.ScopeSHA256) ||
		!marketSHA.MatchString(c.ServerCASHA256) || !marketSHA.MatchString(c.ServerCertificateSHA256) ||
		!nativeRPCURL(c.BaseURL, true) || u.Path != "" || !nativeRPCURL(c.HealthURL, false) || len(c.AllowedCapabilities) < 1 || len(c.AllowedCapabilities) > 2 {
		return nil, errNativeWorkerRPC
	}
	allowed := map[string]bool{}
	for _, cap := range c.AllowedCapabilities {
		if allowed[cap] || cap != "ensure_native_worker" && cap != "destroy_native_worker" && cap != "observe_native_worker" {
			return nil, errNativeWorkerRPC
		}
		allowed[cap] = true
	}
	if allowed["observe_native_worker"] && len(allowed) != 1 {
		return nil, errNativeWorkerRPC
	}
	ca, e := nativePrivateReadFile(c.ServerCAFile, 65536, false)
	if e != nil || nativeRPCHash(ca) != c.ServerCASHA256 {
		return nil, errNativeWorkerRPC
	}
	pool, e := nativeRPCCAPool(ca)
	if e != nil {
		return nil, errNativeWorkerRPC
	}
	cert, e := nativePrivateReadFile(c.ClientCertificateFile, 65536, false)
	if e != nil {
		return nil, errNativeWorkerRPC
	}
	remaining, certificateCount := cert, 0
	for len(bytes.TrimSpace(remaining)) > 0 {
		if !bytes.HasPrefix(bytes.TrimSpace(remaining), []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, errNativeWorkerRPC
		}
		block, rest := pem.Decode(remaining)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, errNativeWorkerRPC
		}
		if _, e := x509.ParseCertificate(block.Bytes); e != nil {
			return nil, errNativeWorkerRPC
		}
		certificateCount++
		remaining = rest
	}
	if certificateCount < 1 || certificateCount > 8 {
		return nil, errNativeWorkerRPC
	}
	key, e := nativePrivateReadFile(c.ClientKeyFile, 32768, true)
	if e != nil {
		return nil, errNativeWorkerRPC
	}
	defer nativePrivateWipe(key)
	pair, e := tls.X509KeyPair(cert, key)
	if e != nil || len(pair.Certificate) < 1 || len(pair.Certificate) > 8 {
		return nil, errNativeWorkerRPC
	}
	leaf, e := x509.ParseCertificate(pair.Certificate[0])
	if e != nil || !nativeRPCLeaf(leaf, x509.ExtKeyUsageClientAuth) {
		return nil, errNativeWorkerRPC
	}
	pair.Leaf = leaf
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool, Certificates: []tls.Certificate{pair},
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.VerifiedChains) < 1 || len(state.PeerCertificates) < 1 || nativeRPCHash(state.PeerCertificates[0].Raw) != c.ServerCertificateSHA256 || !nativeRPCLeaf(state.PeerCertificates[0], x509.ExtKeyUsageServerAuth) {
				return errNativeWorkerRPC
			}
			return nil
		}}
	noRedirect := func(*http.Request, []*http.Request) error { return errNativeWorkerRPC }
	c.AllowedCapabilities = append([]string(nil), c.AllowedCapabilities...)
	return &NativeWorkerRPCClient{&nativeWorkerRPCState{config: c, allowed: allowed, leaf: leaf,
		tlsClient: &http.Client{Transport: nativeRPCTransport(tlsConfig), CheckRedirect: noRedirect},
		health:    &http.Client{Transport: nativeRPCTransport(nil), CheckRedirect: noRedirect}}}, nil
}

func (c *NativeWorkerRPCClient) Matches(adapter model.CapacityMarketAdapterBinding, profile, binding, source, scope, capability string) bool {
	if c == nil || c.nativeWorkerRPCState == nil {
		return false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return !c.closed && c.config.Adapter == adapter && c.config.Profile == profile && c.config.BindingName == binding &&
		c.config.SDKSourceCommit == source && c.config.ScopeSHA256 == scope && c.allowed[capability]
}

// ScopeValid is checked before the original resolver can hydrate credentials.
// Only an already selected private handle is consulted; inputs select no files.
func (c *NativeWorkerRPCClient) ScopeValid(adapter model.CapacityMarketAdapterBinding, base string) bool {
	if c == nil || c.nativeWorkerRPCState == nil {
		return false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return !c.closed && c.config.Adapter == adapter && c.config.BaseURL == base
}

func nativeRPCDeadline(ctx context.Context) bool {
	if ctx == nil || ctx.Err() != nil {
		return false
	}
	d, ok := ctx.Deadline()
	return ok && d.After(time.Now()) && !d.After(time.Now().Add(90*time.Second))
}

// Call owns exactly one HTTP send and its actual bounded Read and Close. It
// authenticates the server chain, hostname, exact leaf and compiled Source.
func (c *NativeWorkerRPCClient) Call(ctx context.Context, target string, raw []byte, limit int64) ([]byte, error) {
	if c == nil || c.nativeWorkerRPCState == nil || !nativeRPCDeadline(ctx) || limit < 1 || limit > 2<<20 || len(raw) < 2 || len(raw) > 2<<20 {
		return nil, errNativeWorkerRPC
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.closed || !nativeRPCLeaf(c.leaf, x509.ExtKeyUsageClientAuth) {
		return nil, errNativeWorkerRPC
	}
	switch target {
	case c.config.BaseURL + "/rpc/describe":
		var request model.AdapterDescribeRequest
		if DecodeNativeCapacity(json.RawMessage(raw), &request) != nil || request.Provider == "" || request.ExpectedVersion == "" {
			return nil, errNativeWorkerRPC
		}
	case c.config.BaseURL + "/rpc/execute":
		var request model.AdapterExecuteIntegrationRequest
		if DecodeNativeCapacity(json.RawMessage(raw), &request) != nil || request.Operation != request.Capability || !c.allowed[request.Capability] || len(request.Auth) != 0 || len(request.Metadata) != 0 || request.Input["binding_name"] != c.config.BindingName {
			return nil, errNativeWorkerRPC
		}
		// ManifestReference carries IDs/versions, not checksums. The private
		// resolver checks original row checksums before credential hydration.
		if request.Integration.Instance.ID.String() != c.config.Adapter.ManifestID || request.Integration.Instance.Version != c.config.Adapter.Version || request.Integration.Instance.Kind != "integration_instance" || request.Integration.Type.ID.String() != c.config.Adapter.IntegrationTypeID || request.Integration.Type.Kind != "integration_type" {
			return nil, errNativeWorkerRPC
		}
	default:
		return nil, errNativeWorkerRPC
	}
	return c.original(ctx, c.tlsClient, http.MethodPost, target, raw, limit, true)
}

// This fixed, unauthenticated public health read is diagnostic only. The TLS
// client certificate is never offered to the separate health listener.
func (c *NativeWorkerRPCClient) Probe(ctx context.Context) error {
	if c == nil || c.nativeWorkerRPCState == nil || !nativeRPCDeadline(ctx) {
		return errNativeWorkerRPC
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.closed {
		return errNativeWorkerRPC
	}
	_, e := c.original(ctx, c.health, http.MethodGet, c.config.HealthURL, nil, 4096, false)
	return e
}

func (c *NativeWorkerRPCClient) original(ctx context.Context, client *http.Client, method, target string, raw []byte, limit int64, requireSource bool) ([]byte, error) {
	request, e := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(raw))
	if e != nil {
		return nil, errNativeWorkerRPC
	}
	request.GetBody = nil // A consumed original can never be replayed.
	request.Header.Set("Content-Type", "application/json")
	reply, callErr := client.Do(request)
	var body []byte
	var readErr, closeErr error
	valid := callErr == nil && reply != nil && reply.Body != nil && reply.StatusCode == http.StatusOK && reply.Request != nil && reply.Request.URL != nil && reply.Request.URL.String() == target && reply.Request.Method == method
	if requireSource && valid {
		values := reply.Header.Values("X-Yggdrasil-Source-Commit")
		valid = len(values) == 1 && values[0] == c.config.SDKSourceCommit && reply.TLS != nil && len(reply.TLS.VerifiedChains) > 0
	}
	if reply != nil && reply.Body != nil {
		if valid {
			body, readErr = io.ReadAll(io.LimitReader(reply.Body, limit+1))
		}
		closeErr = reply.Body.Close()
	}
	if !valid || errors.Join(callErr, readErr, closeErr, ctx.Err()) != nil || !nativeRPCDeadline(ctx) || int64(len(body)) > limit {
		return nil, errNativeWorkerRPC
	}
	return body, nil
}

func (c *NativeWorkerRPCClient) Close() error {
	if c == nil || c.nativeWorkerRPCState == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	c.tlsClient.CloseIdleConnections()
	c.health.CloseIdleConnections()
	c.tlsClient, c.health, c.leaf = nil, nil, nil
	return nil
}
