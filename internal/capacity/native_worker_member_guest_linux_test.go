//go:build linux

package capacity

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// Synthetic CI identities and process facts exercise the actual protected
// codec/transport. They do not claim a running System agent or kubelet.
func nativeMemberGuestFixture(t *testing.T) (*NativeWorkerPrivateFactory, model.CapacityNativeWorkerAttempt, []byte, string) {
	t.Helper()
	f, a, launch := nativeGuestIdentityFixture(t)
	c := *f.config.GuestRead
	c.PlacementBootstrapPolicySHA256 = strings.Repeat("7", 64)
	g, err := newNativeGuestReadIdentity(c)
	if err != nil {
		t.Fatal("explicit placement identity refused", err)
	}
	f.guest.close()
	f.guest = g
	f.config.GuestRead = &c
	f.config.Execution.GuestIdentityPolicySHA256 = g.policySHA256
	a.Execution = f.config.Execution
	prepared, err := f.Prepare(a)
	if err != nil || !bytes.Equal(prepared.PublicJSON, launch) {
		t.Fatal("guest policy opt-in changed immutable Launch v1", err)
	}
	return f, a, launch, c.PlacementBootstrapPolicySHA256
}

func nativeMemberGuestObservation(t *testing.T, f *NativeWorkerPrivateFactory, a model.CapacityNativeWorkerAttempt) model.CapacityNativeWorkerPlacementBootstrapObservation {
	t.Helper()
	name, err := NativeWorkerBootstrapNodeName(a)
	if err != nil {
		t.Fatal("exact sealed birth required", err)
	}
	return model.CapacityNativeWorkerPlacementBootstrapObservation{Schema: model.CapacityNativeWorkerPlacementBootstrapSchema, SourceCommit: f.config.SystemBuildSource, AttemptID: a.ID.String(), LaunchSHA256: a.LaunchSHA256, ProviderID: a.Physical.ProviderID, NodeName: name, ObservedAt: time.Now().UTC(), AgentPID: 103, AgentStartTicks: 991, ActualAgentArgv: []string{"/usr/local/bin/k3s", "agent"}, AgentConfigPath: "/etc/rancher/k3s/config.yaml", ConfiguredKubeletArgs: []string{"register-with-taints=dakasa.io/native-worker-reserved:NoSchedule"}, ConfiguredNodeIPv4: a.OverlayIPv4, AgentConfigComplete: true}
}

func TestNativeMemberGuestPolicyKeepsLegacyBytesAndRequiresNewDurablePin(t *testing.T) {
	f, a, launch := nativeGuestIdentityFixture(t)
	c := *f.config.GuestRead
	// This is the old, explicit public issuance record with no placement field.
	legacy, err := json.Marshal(struct {
		Version           string `json:"version"`
		MasterVersion     string `json:"master_version"`
		MasterPublicKey   string `json:"master_public_key"`
		IssuerCA          string `json:"issuer_ca_sha256"`
		NetworkTemplate   string `json:"network_template_sha256"`
		ValiditySeconds   int64  `json:"certificate_validity_seconds"`
		MaxReadAgeSeconds int    `json:"max_read_age_seconds"`
	}{c.Version, c.MasterVersion, c.MasterPublicKey, c.IssuerCASHA256, c.NetworkTemplateSHA256, c.CertificateValiditySeconds, c.MaxReadAgeSeconds})
	if err != nil || NativeWorkerGuestIdentityPolicySHA256(c) != nativePrivateSHA(legacy) || a.Execution.GuestIdentityPolicySHA256 != nativePrivateSHA(legacy) {
		t.Fatal("absent placement option changed the old issuance bytes/hash", err)
	}
	// Execution retains its existing wire. The placement declaration belongs
	// only to the public issuance digest, never a second permission field.
	e := a.Execution
	e.GuestIdentityPolicySHA256 = ""
	oldExecution, err := json.Marshal(struct {
		Profile               string                             `json:"profile"`
		Adapter               model.CapacityMarketAdapterBinding `json:"adapter"`
		BindingName           string                             `json:"binding_name"`
		SDKSourceCommit       string                             `json:"sdk_source_commit"`
		ScopeSHA256           string                             `json:"scope_sha256"`
		EnsureCapability      string                             `json:"ensure_capability"`
		ObserveCapability     string                             `json:"observe_capability"`
		DestroyCapability     string                             `json:"destroy_capability"`
		LaunchTemplateSHA256  string                             `json:"launch_template_sha256"`
		BootstrapSourceCommit string                             `json:"bootstrap_source_commit"`
		IPAMScope             string                             `json:"ipam_scope"`
		OverlayCIDR           string                             `json:"overlay_cidr"`
		ExcludedIPv4          []string                           `json:"excluded_ipv4"`
	}{e.Profile, e.Adapter, e.BindingName, e.SDKSourceCommit, e.ScopeSHA256, e.EnsureCapability, e.ObserveCapability, e.DestroyCapability, e.LaunchTemplateSHA256, e.BootstrapSourceCommit, e.IPAMScope, e.OverlayCIDR, e.ExcludedIPv4})
	currentExecution, currentErr := json.Marshal(e)
	if err != nil || currentErr != nil || !bytes.Equal(oldExecution, currentExecution) {
		t.Fatal("legacy Execution acquired a new field or changed bytes", err, currentErr)
	}
	before, err := f.guest.derive(a, launch, f.config.SystemBuildSource)
	if err != nil {
		t.Fatal(err)
	}
	defer before.close()
	c.PlacementBootstrapPolicySHA256 = strings.Repeat("7", 64)
	g, err := newNativeGuestReadIdentity(c)
	if err != nil {
		t.Fatal(err)
	}
	defer g.close()
	if g.policySHA256 == f.guest.policySHA256 || !marketSHA.MatchString(g.policySHA256) || NativeWorkerGuestIdentityPolicySHA256(c) != g.policySHA256 {
		t.Fatal("explicit placement opt-in did not bind a different issuance policy")
	}
	if cert, err := g.derive(a, launch, f.config.SystemBuildSource); err == nil {
		cert.close()
		t.Fatal("new option adopted an old Attempt without its durable issuance pin")
	}
	opted := a
	opted.Execution.GuestIdentityPolicySHA256 = g.policySHA256
	first, err := g.derive(opted, launch, f.config.SystemBuildSource)
	if err != nil {
		t.Fatal(err)
	}
	defer first.close()
	second, err := g.derive(opted, launch, f.config.SystemBuildSource)
	if err != nil {
		t.Fatal(err)
	}
	defer second.close()
	if !bytes.Equal(first.certificateDER, second.certificateDER) || !bytes.Equal(first.privateKeyDER, second.privateKeyDER) || bytes.Equal(first.certificateDER, before.certificateDER) || !first.notAfter.Equal(before.notAfter) || !first.notAfter.Equal(a.CreatedAt.UTC().Truncate(time.Second).Add(time.Duration(c.CertificateValiditySeconds)*time.Second)) {
		t.Fatal("retry reminted identity or opt-in renewed immutable certificate validity")
	}
	leaf, err := x509.ParseCertificate(first.certificateDER)
	if err != nil || !leaf.NotBefore.Equal(a.CreatedAt.UTC().Truncate(time.Second)) || !leaf.NotAfter.Equal(first.notAfter) {
		t.Fatal("actual certificate validity differs from immutable Attempt creation", err)
	}
	for _, fault := range []string{"missing-pin", "old-pin", "extended-validity"} {
		t.Run(fault, func(t *testing.T) {
			bad := opted
			local := *g
			switch fault {
			case "missing-pin":
				bad.Execution.GuestIdentityPolicySHA256 = ""
			case "old-pin":
				bad.Execution.GuestIdentityPolicySHA256 = a.Execution.GuestIdentityPolicySHA256
			case "extended-validity":
				local.config.CertificateValiditySeconds++
				local.policySHA256 = NativeWorkerGuestIdentityPolicySHA256(local.config)
			}
			if cert, err := local.derive(bad, launch, f.config.SystemBuildSource); err == nil {
				cert.close()
				t.Fatal("unbound policy revision derived a certificate")
			}
		})
	}
	for _, invalid := range []string{"short", strings.Repeat("A", 64), strings.Repeat("7", 63) + "g"} {
		bad := c
		bad.PlacementBootstrapPolicySHA256 = invalid
		if identity, err := newNativeGuestReadIdentity(bad); err == nil {
			identity.close()
			t.Fatal("noncanonical optional policy pin accepted")
		}
	}
	if f.MatchesPlacementBootstrapPolicy(c.PlacementBootstrapPolicySHA256) || (*NativeWorkerPrivateFactory)(nil).MatchesPlacementBootstrapPolicy(c.PlacementBootstrapPolicySHA256) {
		t.Fatal("legacy or nil factory advertised opt-in authority")
	}
}

func TestNativeMemberGuestPlacementUsesActualMTLSAndOneFixedGET(t *testing.T) {
	f, a, launch, policy := nativeMemberGuestFixture(t)
	source := f.config.SystemBuildSource
	serverCert, err := f.guest.derive(a, launch, source)
	if err != nil {
		t.Fatal(err)
	}
	defer serverCert.close()
	clientCert, err := f.guest.deriveClient(a, launch, source)
	if err != nil {
		t.Fatal(err)
	}
	defer clientCert.close()
	pair, err := tls.X509KeyPair(serverCert.certificatePEM, serverCert.privateKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(f.guest.issuer)
	var calls, dials atomic.Int32
	var mode atomic.Value
	mode.Store("valid")
	out := nativeMemberGuestObservation(t, f, a)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != http.MethodGet || r.URL.RequestURI() != model.CapacityNativeWorkerPlacementBootstrapPath || r.Host != net.JoinHostPort(a.OverlayIPv4, "9445") || r.Body != http.NoBody || r.ContentLength != 0 || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) != 1 || nativePrivateSHA(r.TLS.PeerCertificates[0].Raw) != clientCert.fingerprint || len(r.TLS.PeerCertificates[0].URIs) != 1 || r.TLS.PeerCertificates[0].URIs[0].String() != clientCert.uri {
			t.Error("fixed GET0 or actual per-Attempt client identity changed")
		}
		w.Header().Set("X-Yggdrasil-Source-Commit", source)
		w.Header().Set("Content-Type", "application/json")
		current := out
		current.ObservedAt = time.Now().UTC()
		switch mode.Load().(string) {
		case "wrong-source-header":
			w.Header().Set("X-Yggdrasil-Source-Commit", strings.Repeat("b", 40))
		case "duplicate-source-header":
			w.Header().Add("X-Yggdrasil-Source-Commit", source)
		case "redirect":
			w.Header().Set("Location", "https://example.invalid")
			w.WriteHeader(http.StatusTemporaryRedirect)
			return
		case "wrong-schema":
			current.Schema += "-wrong"
		case "wrong-source-body":
			current.SourceCommit = strings.Repeat("b", 40)
		case "wrong-attempt":
			current.AttemptID = "33333333-3333-4333-8333-333333333333"
		case "wrong-launch":
			current.LaunchSHA256 = strings.Repeat("8", 64)
		case "wrong-provider":
			current.ProviderID = "aws:///us-east-1a/i-22222222222222222"
		case "wrong-node":
			current.NodeName += "-foreign"
		case "wrong-ip":
			current.ConfiguredNodeIPv4 = "10.81.0.8"
		case "incomplete-config":
			current.AgentConfigComplete = false
		case "no-agent":
			current.AgentPID = 0
		case "no-start-ticks":
			current.AgentStartTicks = 0
		case "no-config-path":
			current.AgentConfigPath = ""
		case "nil-argv":
			current.ActualAgentArgv = nil
		case "nil-kubelet-args":
			current.ConfiguredKubeletArgs = nil
		case "future":
			current.ObservedAt = time.Now().Add(time.Minute)
		case "stale":
			current.ObservedAt = time.Now().Add(-time.Hour)
		case "empty-body":
			return
		case "null-body":
			_, _ = io.WriteString(w, "null")
			return
		case "extra-field":
			raw, err := json.Marshal(current)
			if err != nil {
				t.Error(err)
				return
			}
			_, _ = w.Write(append(raw[:len(raw)-1], []byte(`,"permission":true}`)...))
			return
		}
		_ = json.NewEncoder(w).Encode(current)
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}, ClientCAs: pool, ClientAuth: tls.RequireAndVerifyClientCert, VerifyConnection: func(state tls.ConnectionState) error {
		if len(state.VerifiedChains) == 0 || len(state.PeerCertificates) != 1 || nativePrivateSHA(state.PeerCertificates[0].Raw) != clientCert.fingerprint || len(state.PeerCertificates[0].URIs) != 1 || state.PeerCertificates[0].URIs[0].String() != clientCert.uri {
			return errors.New("synthetic CI guest rejects foreign per-Attempt client")
		}
		return nil
	}}
	server.StartTLS()
	defer server.Close()
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		dials.Add(1)
		if network != "tcp" || address != net.JoinHostPort(a.OverlayIPv4, "9445") {
			return nil, errors.New("fixed overlay endpoint changed")
		}
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}
	read := func(ctx context.Context, attempt model.CapacityNativeWorkerAttempt, raw []byte, expectedSource, expectedPolicy string) (model.CapacityNativeWorkerPlacementBootstrapObservation, error) {
		return f.guest.readPlacementBootstrap(ctx, attempt, raw, expectedSource, expectedPolicy, dial)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	got, err := read(ctx, a, launch, source, policy)
	if err != nil || got.AttemptID != a.ID.String() || got.NodeName != out.NodeName || !reflect.DeepEqual(got.ActualAgentArgv, out.ActualAgentArgv) || calls.Load() != 1 || dials.Load() != 1 || !f.MatchesPlacementBootstrapPolicy(policy) {
		t.Fatal("authenticated placement bootstrap did not return the bound facts exactly once", err)
	}
	for _, fault := range []string{"wrong-source-header", "duplicate-source-header", "redirect", "wrong-schema", "wrong-source-body", "wrong-attempt", "wrong-launch", "wrong-provider", "wrong-node", "wrong-ip", "incomplete-config", "no-agent", "no-start-ticks", "no-config-path", "nil-argv", "nil-kubelet-args", "future", "stale", "empty-body", "null-body", "extra-field"} {
		t.Run(fault, func(t *testing.T) {
			mode.Store(fault)
			beforeCalls, beforeDials := calls.Load(), dials.Load()
			got, err := read(ctx, a, launch, source, policy)
			if err == nil || !reflect.DeepEqual(got, model.CapacityNativeWorkerPlacementBootstrapObservation{}) || calls.Load() != beforeCalls+1 || dials.Load() != beforeDials+1 {
				t.Fatal("invalid return gained facts or caused retry", fault, err)
			}
		})
	}
	mode.Store("valid")
	for _, fault := range []string{"nil-context", "no-deadline", "cancelled", "no-policy", "wrong-policy", "missing-issuance-pin", "legacy-attempt-pin", "nil-physical", "invalid-physical", "empty-provider", "wrong-source", "changed-launch", "expired-certificate"} {
		t.Run(fault, func(t *testing.T) {
			bad := a
			physical := *a.Physical
			bad.Physical = &physical
			localContext, raw, expectedSource, expectedPolicy := ctx, launch, source, policy
			switch fault {
			case "nil-context":
				localContext = nil
			case "no-deadline":
				localContext = context.Background()
			case "cancelled":
				var stop context.CancelFunc
				localContext, stop = context.WithCancel(ctx)
				stop()
			case "no-policy":
				expectedPolicy = ""
			case "wrong-policy":
				expectedPolicy = strings.Repeat("8", 64)
			case "missing-issuance-pin":
				bad.Execution.GuestIdentityPolicySHA256 = ""
			case "legacy-attempt-pin":
				legacyConfig := f.guest.config
				legacyConfig.PlacementBootstrapPolicySHA256 = ""
				bad.Execution.GuestIdentityPolicySHA256 = NativeWorkerGuestIdentityPolicySHA256(legacyConfig)
			case "nil-physical":
				bad.Physical = nil
			case "invalid-physical":
				bad.Physical.PhysicalBindingSHA256 = ""
			case "empty-provider":
				bad.Physical.ProviderID = ""
			case "wrong-source":
				expectedSource = strings.Repeat("b", 40)
			case "changed-launch":
				raw = append(bytes.Clone(launch), ' ')
			case "expired-certificate":
				bad.CreatedAt = a.CreatedAt.Add(-2 * time.Hour)
			}
			before := dials.Load()
			got, err := read(localContext, bad, raw, expectedSource, expectedPolicy)
			if err == nil || !reflect.DeepEqual(got, model.CapacityNativeWorkerPlacementBootstrapObservation{}) || dials.Load() != before {
				t.Fatal("unbound, expired or incomplete authority reached the socket", fault, err)
			}
		})
	}
	// Every replacement below is a real CA-signed leaf. Keeping hostname and
	// EKU valid in the leaf-only case isolates the deterministic DER pin.
	for _, fault := range []string{"server-ca", "server-leaf", "server-san", "server-uri", "server-role"} {
		t.Run(fault, func(t *testing.T) {
			leaf, err := x509.ParseCertificate(serverCert.certificateDER)
			if err != nil {
				t.Fatal(err)
			}
			leaf.SerialNumber = new(big.Int).Add(leaf.SerialNumber, big.NewInt(1))
			issuer, issuerKey := f.guest.issuer, f.guest.issuerKey
			switch fault {
			case "server-ca":
				foreignKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{11}, ed25519.SeedSize))
				defer nativePrivateWipe(foreignKey)
				foreignCA := *f.guest.issuer
				foreignCA.Subject.CommonName = "synthetic-untrusted-placement-issuer"
				foreignCA.RawSubject = nil
				foreignCA.PublicKey = foreignKey.Public()
				caDER, err := x509.CreateCertificate(nil, &foreignCA, &foreignCA, foreignKey.Public(), foreignKey)
				if err != nil {
					t.Fatal(err)
				}
				issuer, err = x509.ParseCertificate(caDER)
				if err != nil {
					t.Fatal(err)
				}
				issuerKey = foreignKey
			case "server-san":
				leaf.IPAddresses = []net.IP{net.ParseIP("10.81.0.8")}
			case "server-uri":
				leaf.URIs = []*url.URL{{Scheme: "spiffe", Host: "dakasa", Path: "/foreign-attempt"}}
			case "server-role":
				leaf.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
			}
			der, err := x509.CreateCertificate(nil, leaf, issuer, leaf.PublicKey, issuerKey)
			if err != nil {
				t.Fatal(err)
			}
			badPair := pair
			badPair.Certificate = [][]byte{der}
			badPair.Leaf = nil
			var served atomic.Int32
			badServer := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { served.Add(1) }))
			badServer.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{badPair}, ClientCAs: pool, ClientAuth: tls.RequireAndVerifyClientCert}
			badServer.StartTLS()
			defer badServer.Close()
			var attempted atomic.Int32
			privateDial := func(ctx context.Context, network, address string) (net.Conn, error) {
				attempted.Add(1)
				if network != "tcp" || address != net.JoinHostPort(a.OverlayIPv4, "9445") {
					return nil, errors.New("foreign endpoint")
				}
				return (&net.Dialer{}).DialContext(ctx, network, badServer.Listener.Addr().String())
			}
			got, err := f.guest.readPlacementBootstrap(ctx, a, launch, source, policy, privateDial)
			if err == nil || !reflect.DeepEqual(got, model.CapacityNativeWorkerPlacementBootstrapObservation{}) || served.Load() != 0 || attempted.Load() != 1 {
				t.Fatal("foreign signed leaf reached HTTP or supplied bootstrap facts", fault, err)
			}
		})
	}
	if _, err := (*nativeGuestReadIdentity)(nil).readPlacementBootstrap(ctx, a, launch, source, policy, dial); err == nil {
		t.Fatal("nil guest identity supplied placement facts")
	}
	if _, err := (*NativeWorkerPrivateFactory)(nil).ReadPlacementBootstrap(ctx, a, json.RawMessage(launch), policy); err == nil {
		t.Fatal("nil public factory supplied placement facts")
	}
	unbound := a
	unbound.Execution.GuestIdentityPolicySHA256 = ""
	if _, err := f.ReadPlacementBootstrap(ctx, unbound, json.RawMessage(launch), policy); err == nil {
		t.Fatal("public factory accepted an Attempt without its issuance pin")
	}
	if err := f.Close(); err != nil || f.MatchesPlacementBootstrapPolicy(policy) {
		t.Fatal("closed factory retained placement capability", err)
	}
	if _, err := f.ReadPlacementBootstrap(ctx, a, json.RawMessage(launch), policy); err == nil {
		t.Fatal("closed public factory retained the read port")
	}
}

func TestNativeMemberGuestPlacementOriginalRequiresReadCloseSourceAndContext(t *testing.T) {
	f, a, launch, _ := nativeMemberGuestFixture(t)
	cert, err := f.guest.derive(a, launch, f.config.SystemBuildSource)
	if err != nil {
		t.Fatal(err)
	}
	defer cert.close()
	leaf, err := x509.ParseCertificate(cert.certificateDER)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(f.guest.issuer)
	chains, err := leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: a.OverlayIPv4, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
	if err != nil {
		t.Fatal(err)
	}
	original, err := json.Marshal(nativeMemberGuestObservation(t, f, a))
	if err != nil {
		t.Fatal(err)
	}
	target := "https://" + net.JoinHostPort(a.OverlayIPv4, "9445") + model.CapacityNativeWorkerPlacementBootstrapPath
	u, err := url.Parse(target)
	if err != nil {
		t.Fatal(err)
	}
	// Fault-injected response bodies exercise the same original-return helper
	// after certificate verification. Actual TLS is covered in the root above.
	for _, fault := range []string{"valid", "read", "close", "cancel-at-close", "transport-with-response", "wrong-source", "duplicate-source", "wrong-content-type", "wrong-target", "wrong-method", "missing-tls", "http-failure", "oversized"} {
		t.Run(fault, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			body := &nativeGuestReturnBody{data: bytes.Clone(original), readErr: io.EOF}
			r := &http.Response{StatusCode: http.StatusOK, Header: http.Header{"X-Yggdrasil-Source-Commit": []string{f.config.SystemBuildSource}, "Content-Type": []string{"application/json"}}, Body: body, Request: &http.Request{Method: http.MethodGet, URL: u}, TLS: &tls.ConnectionState{VerifiedChains: chains}}
			var transportErr error
			unread := false
			switch fault {
			case "read":
				body.readErr = io.ErrUnexpectedEOF
			case "close":
				body.closeErr = errors.New("synthetic original close failed")
			case "cancel-at-close":
				body.cancel = cancel
			case "transport-with-response":
				transportErr, unread = errors.New("synthetic incomplete transport"), true
			case "wrong-source":
				r.Header.Set("X-Yggdrasil-Source-Commit", strings.Repeat("b", 40))
				unread = true
			case "duplicate-source":
				r.Header.Add("X-Yggdrasil-Source-Commit", f.config.SystemBuildSource)
				unread = true
			case "wrong-content-type":
				r.Header.Set("Content-Type", "text/plain")
				unread = true
			case "wrong-target":
				changed := *u
				changed.Path = NativeWorkerGuestWitnessPath
				r.Request.URL = &changed
				unread = true
			case "wrong-method":
				r.Request.Method, unread = http.MethodPost, true
			case "missing-tls":
				r.TLS, unread = nil, true
			case "http-failure":
				r.StatusCode, unread = http.StatusServiceUnavailable, true
			case "oversized":
				body.data = bytes.Repeat([]byte{'x'}, (64<<10)+1)
			}
			raw, err := nativeGuestOriginalRead(ctx, r, transportErr, target, f.config.SystemBuildSource)
			if body.closes != 1 || (fault == "valid") != (err == nil) || unread && body.reads != 0 || err != nil && raw != nil {
				t.Fatal("failed original became evidence or skipped original Close", fault, err, body.reads, body.closes)
			}
			if fault == "valid" && !bytes.Equal(raw, original) {
				t.Fatal("successful original bytes changed before interpretation")
			}
		})
	}
}
