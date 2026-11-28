//go:build linux

package capacity

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func nativeGuestWitnessFixture(t *testing.T, f *NativeWorkerPrivateFactory, a model.CapacityNativeWorkerAttempt, launch []byte) model.CapacityNativeWorkerGuestWitness {
	t.Helper()
	var l nativePrivateLaunch
	if json.Unmarshal(launch, &l) != nil {
		t.Fatal("invalid fixture launch")
	}
	n := f.guest.network
	return model.CapacityNativeWorkerGuestWitness{Schema: "native_worker_guest_network_witness_v1", SystemSourceCommit: l.SourceCommit, AttemptID: a.ID.String(), LaunchSHA256: a.LaunchSHA256, BindingSHA256: a.Physical.PhysicalBindingSHA256, NetworkTemplateSHA256: f.guest.config.NetworkTemplateSHA256, ObservedAt: time.Now().UTC(), InterfaceName: n.Interface, InterfaceIndex: 7, MTU: n.MTU, InterfaceUp: true, WorkerIPv4Present: true, WireGuardPublicKey: l.Network.WorkerPublicKey, FloorPeerPublicKey: l.Network.FloorPeerPublicKey, FloorPeerEndpoint: l.Network.FloorPeerEndpoint, FloorPeerLastHandshakeUnix: time.Now().Add(-time.Second).Unix(), Routes: []model.CapacityNativeWorkerGuestRoute{{TargetIPv4: "10.80.0.2", Device: n.Interface, SourceIPv4: a.OverlayIPv4}, {TargetIPv4: n.ClusterDNSIPv4, Device: n.Interface, SourceIPv4: a.OverlayIPv4}, {TargetIPv4: "10.83.0.1", Device: n.Interface, SourceIPv4: a.OverlayIPv4}}, DNSName: n.DNSName, DNSResolverIPv4: n.ClusterDNSIPv4, DNSAnswerIPv4: []string{"10.83.0.1"}, FloorTLSVerified: true}
}

type nativeGuestReturnBody struct {
	data              []byte
	readErr, closeErr error
	reads, closes     int
	cancel            context.CancelFunc
}

func (b *nativeGuestReturnBody) Read(dst []byte) (int, error) {
	b.reads++
	if len(b.data) > 0 {
		n := copy(dst, b.data)
		b.data = b.data[n:]
		return n, nil
	}
	return 0, b.readErr
}
func (b *nativeGuestReturnBody) Close() error {
	b.closes++
	if b.cancel != nil {
		b.cancel()
	}
	return b.closeErr
}

func TestNativeGuestOriginalReturnRequiresSourceReadCloseAndLiveContext(t *testing.T) {
	for _, fault := range []string{"none", "read", "close", "cancel-at-close", "source", "transport-with-response", "oversized"} {
		t.Run(fault, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			body := &nativeGuestReturnBody{data: []byte(`{"actual":"original"}`), readErr: io.EOF}
			u, _ := url.Parse("https://10.81.0.7:9445" + NativeWorkerGuestWitnessPath)
			r := &http.Response{StatusCode: 200, Header: http.Header{"X-Yggdrasil-Source-Commit": []string{strings.Repeat("a", 40)}, "Content-Type": []string{"application/json"}}, Body: body, Request: &http.Request{Method: http.MethodGet, URL: u}, TLS: &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{{}}}}}
			var callErr error
			switch fault {
			case "read":
				body.readErr = io.ErrUnexpectedEOF
			case "close":
				body.closeErr = errors.New("original close failed")
			case "cancel-at-close":
				body.cancel = cancel
			case "source":
				r.Header.Set("X-Yggdrasil-Source-Commit", strings.Repeat("b", 40))
			case "transport-with-response":
				callErr = errors.New("transport failed")
			case "oversized":
				body.data = bytes.Repeat([]byte{'x'}, (64<<10)+1)
			}
			raw, err := nativeGuestOriginalRead(ctx, r, callErr, u.String(), strings.Repeat("a", 40))
			if body.closes != 1 || (fault == "none") != (err == nil) {
				t.Fatal("original Read/Close/context failure changed disposition", err, body.reads, body.closes)
			}
			if fault == "none" && !bytes.Equal(raw, []byte(`{"actual":"original"}`)) {
				t.Fatal("original bytes replaced")
			}
			if (fault == "source" || fault == "transport-with-response") && body.reads != 0 {
				t.Fatal("unqualified response read before Source/transport check")
			}
			if err != nil && raw != nil {
				t.Fatal("failed original returned decoded evidence")
			}
		})
	}
}

func TestNativeGuestReadUsesActualMTLSFixedHostAndSingleBoundedGET(t *testing.T) {
	f, a, launch := nativeGuestIdentityFixture(t)
	serverCert, err := f.guest.derive(a, launch, f.config.SystemBuildSource)
	if err != nil {
		t.Fatal(err)
	}
	defer serverCert.close()
	clientCert, err := f.guest.deriveClient(a, launch, f.config.SystemBuildSource)
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
	var calls atomic.Int32
	var fault atomic.Int32
	out := nativeGuestWitnessFixture(t, f, a, launch)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != http.MethodGet || r.URL.RequestURI() != NativeWorkerGuestWitnessPath || r.Host != net.JoinHostPort(a.OverlayIPv4, "9445") || r.ContentLength != 0 || r.Body != http.NoBody || len(r.TLS.VerifiedChains) < 1 || nativePrivateSHA(r.TLS.PeerCertificates[0].Raw) != clientCert.fingerprint {
			t.Error("actual mTLS/request identity changed")
		}
		w.Header().Set("X-Yggdrasil-Source-Commit", f.config.SystemBuildSource)
		w.Header().Set("Content-Type", "application/json")
		switch fault.Load() {
		case 1:
			w.Header().Set("X-Yggdrasil-Source-Commit", strings.Repeat("b", 40))
		case 2:
			w.Header().Add("X-Yggdrasil-Source-Commit", f.config.SystemBuildSource)
		case 3:
			w.Header().Set("Location", "https://example.invalid")
			w.WriteHeader(http.StatusTemporaryRedirect)
			return
		case 4:
			_ = json.NewEncoder(w).Encode(map[string]any{"schema": out.Schema})
			return
		}
		_ = json.NewEncoder(w).Encode(out)
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}, ClientCAs: pool, ClientAuth: tls.RequireAndVerifyClientCert}
	server.StartTLS()
	defer server.Close()
	var dials atomic.Int32
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		dials.Add(1)
		if network != "tcp" || address != net.JoinHostPort(a.OverlayIPv4, "9445") {
			return nil, errors.New("foreign endpoint")
		}
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	got, err := f.guest.read(ctx, a, launch, f.config.SystemBuildSource, dial)
	if err != nil || got.EndToEndPathMTUQualified || got.IndependentNetworkQualified || got.UsefulCapacityQualified || got.SchedulingAdmitted || calls.Load() != 1 || dials.Load() != 1 {
		t.Fatal("authentic local witness failed or claimed readiness", err)
	}
	for _, mode := range []int32{1, 2, 3, 4} {
		fault.Store(mode)
		before := calls.Load()
		if _, err := f.guest.read(ctx, a, launch, f.config.SystemBuildSource, dial); err == nil || calls.Load() != before+1 {
			t.Fatal("Source/closed DTO/redirect failure accepted or retried", mode, err)
		}
	}
	bad := a
	bad.Execution.GuestIdentityPolicySHA256 = ""
	before := dials.Load()
	if _, err := f.guest.read(ctx, bad, launch, f.config.SystemBuildSource, dial); err == nil || dials.Load() != before {
		t.Fatal("unbound identity reached network")
	}
}

func TestNativeGuestReadRefusesCoherentLocalClaimsAndNeverFillsReadiness(t *testing.T) {
	f, a, launch := nativeGuestIdentityFixture(t)
	var l nativePrivateLaunch
	_ = json.Unmarshal(launch, &l)
	for _, fault := range []string{"future", "stale", "binding", "launch", "attempt", "source", "template", "mtu", "down", "missing-ip", "wrong-wg", "peer", "endpoint", "stale-handshake", "future-handshake", "dns-name", "dns-server", "foreign-answer", "duplicate-answer", "missing-route", "extra-route", "wrong-route-source", "no-floor-tls", "path-qualified", "network-qualified", "admitted", "useful"} {
		t.Run(fault, func(t *testing.T) {
			o := nativeGuestWitnessFixture(t, f, a, launch)
			switch fault {
			case "future":
				o.ObservedAt = time.Now().Add(time.Second)
			case "stale":
				o.ObservedAt = time.Now().Add(-time.Hour)
			case "binding":
				o.BindingSHA256 = strings.Repeat("0", 64)
			case "launch":
				o.LaunchSHA256 = strings.Repeat("0", 64)
			case "attempt":
				o.AttemptID = "foreign"
			case "source":
				o.SystemSourceCommit = strings.Repeat("0", 40)
			case "template":
				o.NetworkTemplateSHA256 = strings.Repeat("0", 64)
			case "mtu":
				o.MTU = 1500
			case "down":
				o.InterfaceUp = false
			case "missing-ip":
				o.WorkerIPv4Present = false
			case "wrong-wg":
				o.WireGuardPublicKey = o.FloorPeerPublicKey
			case "peer":
				o.FloorPeerPublicKey = o.WireGuardPublicKey
			case "endpoint":
				o.FloorPeerEndpoint = "203.0.113.3:51820"
			case "stale-handshake":
				o.FloorPeerLastHandshakeUnix = time.Now().Add(-time.Hour).Unix()
			case "future-handshake":
				o.FloorPeerLastHandshakeUnix = time.Now().Add(time.Hour).Unix()
			case "dns-name":
				o.DNSName = "caller.example"
			case "dns-server":
				o.DNSResolverIPv4 = "8.8.8.8"
			case "foreign-answer":
				o.DNSAnswerIPv4[0] = "8.8.8.8"
			case "duplicate-answer":
				o.DNSAnswerIPv4 = append(o.DNSAnswerIPv4, o.DNSAnswerIPv4[0])
			case "missing-route":
				o.Routes = o.Routes[:2]
			case "extra-route":
				o.Routes = append(o.Routes, o.Routes[0])
			case "wrong-route-source":
				o.Routes[0].SourceIPv4 = "10.81.0.8"
			case "no-floor-tls":
				o.FloorTLSVerified = false
			case "path-qualified":
				o.EndToEndPathMTUQualified = true
			case "network-qualified":
				o.IndependentNetworkQualified = true
			case "admitted":
				o.SchedulingAdmitted = true
			case "useful":
				o.UsefulCapacityQualified = true
			}
			if nativeGuestWitnessValid(f.guest, a, l, o, time.Now().UTC()) {
				t.Fatal("local report became independent qualification", fault)
			}
		})
	}
	valid := nativeGuestWitnessFixture(t, f, a, launch)
	raw, _ := json.Marshal(valid)
	for _, bad := range [][]byte{bytes.Replace(raw, []byte(`"floor_tls_verified":true`), []byte(`"floor_tls_verified":null`), 1), bytes.Replace(raw, []byte(`"schema":`), []byte(`"Schema":`), 1), bytes.Replace(raw, []byte(`"schema":`), []byte(`"schema":"foreign","schema":`), 1), append(bytes.Clone(raw), []byte(` {}`)...)} {
		var got model.CapacityNativeWorkerGuestWitness
		if nativeWorkerNetworkRPCDecode(bad, &got) == nil {
			t.Fatal("missing/null/alias/duplicate witness accepted")
		}
	}
}
