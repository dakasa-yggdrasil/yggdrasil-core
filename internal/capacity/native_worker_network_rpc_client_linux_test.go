//go:build linux

package capacity

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

func nativeFloorRPCServerLeaf(t *testing.T, p nativeRPCTestPKI, ip string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(19), Subject: pkix.Name{CommonName: "isolated-ci-floor"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.ParseIP(ip)}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, p.ca, key.Public(), p.key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	if err != nil {
		t.Fatal(err)
	}
	return pair
}

type nativeFloorRPCFixture struct {
	client   *NativeWorkerNetworkRPCClient
	config   NativeWorkerNetworkRPCConfig
	binding  model.CapacityNativeWorkerNetworkBinding
	selector model.CapacityNativeWorkerNetworkObserveInput
	server   *httptest.Server
	dial     func(context.Context, string, string) (net.Conn, error)
}

func newNativeFloorRPCFixture(t *testing.T, role string, handler http.Handler, serverIP ...string) nativeFloorRPCFixture {
	t.Helper()
	b := *nativeWorkerNetworkPolicy(t).NativeWorkerLifecycleBinding.Network
	pki := nativeRPCPKI(t)
	certificateIP := b.Floor.NativeIPv4
	if len(serverIP) > 1 {
		t.Fatal("one exact CI certificate IP allowed")
	}
	if len(serverIP) == 1 {
		certificateIP = serverIP[0]
	}
	serverLeaf := nativeFloorRPCServerLeaf(t, pki, certificateIP)
	_, clientPEM, clientKey := pki.leaf(t, x509.ExtKeyUsageClientAuth)
	pool := x509.NewCertPool()
	pool.AddCert(pki.ca)
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{serverLeaf}, ClientCAs: pool, ClientAuth: tls.RequireAndVerifyClientCert}
	server.StartTLS()
	t.Cleanup(server.Close)
	dir := t.TempDir()
	write := func(name string, raw []byte) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	c := NativeWorkerNetworkRPCConfig{Role: role, Floor: b.Floor, Template: b.Template, TemplateSHA256: b.TemplateSHA256, MaxReadAgeSeconds: 30,
		ServerCAFile: write("ca.pem", pki.caPEM), ServerCASHA256: nativeRPCHash(pki.caPEM), ServerCertificateSHA256: nativeRPCHash(serverLeaf.Certificate[0]), ClientCertificateFile: write("client.pem", clientPEM), ClientKeyFile: write("client.key", clientKey)}
	port := "9444"
	if role == "writer" {
		c.AdapterID, c.BindingName, c.SystemSourceCommit, c.ScopeSHA256 = b.Writer.AdapterID, b.Writer.BindingName, b.Writer.SystemSourceCommit, b.Writer.ScopeSHA256
		port = "9443"
	} else {
		c.AdapterID, c.BindingName, c.SystemSourceCommit, c.ScopeSHA256 = b.Reader.AdapterID, b.Reader.BindingName, b.Reader.SystemSourceCommit, b.Reader.ScopeSHA256
	}
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != net.JoinHostPort(b.Floor.NativeIPv4, port) {
			return nil, errors.New("unexpected protected floor destination")
		}
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}
	client, err := newNativeWorkerNetworkRPCClient(c, dial)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	in := model.CapacityNativeWorkerNetworkObserveInput{BindingName: c.BindingName, AttemptID: uuid.NewString(), LaunchSHA256: strings.Repeat("a", 64), WorkerPublicKey: base64.StdEncoding.EncodeToString([]byte(strings.Repeat("w", 32))), WorkerIPv4: "10.90.0.2"}
	return nativeFloorRPCFixture{client, c, b, in, server, dial}
}

func nativeFloorRPCObservation(c NativeWorkerNetworkRPCConfig, in model.CapacityNativeWorkerNetworkObserveInput) model.CapacityNativeWorkerNetworkObservation {
	return model.CapacityNativeWorkerNetworkObservation{Schema: model.CapacityNativeWorkerNetworkObservationSchema, BindingName: c.BindingName, AdapterSourceCommit: c.SystemSourceCommit, ReaderScopeSHA256: c.ScopeSHA256, Requested: in, ObservedAt: time.Now().UTC(), Floor: model.CapacityNativeWorkerNetworkFloorFacts{Bound: c.Floor, Observed: model.CapacityNativeWorkerNetworkHostIdentity{Hostname: c.Floor.NodeName, CASHA256: c.Floor.CASHA256, CAOrigin: "source_bound_local_certificate", NativeInterfaceIndex: 2, NativeInterfaceUp: true, NativeIPv4Present: true}}, NetworkTemplateSHA256: c.TemplateSHA256, MTU: c.Template.MTU, Interface: model.CapacityNativeWorkerNetworkInterfaceFacts{Name: c.Template.Interface, Addresses: []string{}}, Peers: []model.CapacityNativeWorkerNetworkPeerFacts{}, Routes: []model.CapacityNativeWorkerNetworkRouteFacts{}, Firewall: model.CapacityNativeWorkerNetworkFirewallFacts{Chain: "inet/dakasa_native/DAKASA_NATIVE", Rules: []string{}, RulesSHA256: nativePrivateSHA([]byte("\n")), Complete: true}, KernelSettings: model.CapacityNativeWorkerNetworkKernelSettings{IPForward: 1}, KernelInventoryComplete: true}
}

func nativeFloorRPCReply(operation string, out any) []byte {
	raw, _ := json.Marshal(map[string]any{"operation": operation, "capability": operation, "status": "observed", "output": out, "metadata": map[string]bool{"network_admission_qualified": false, "useful_capacity_qualified": false}})
	return raw
}

func TestNativeWorkerFloorRPCRealMTLSFixedRoleSelectorsAndSharedClose(t *testing.T) {
	for _, role := range []string{"reader", "writer"} {
		t.Run(role, func(t *testing.T) {
			var f nativeFloorRPCFixture
			var sends atomic.Int32
			f = newNativeFloorRPCFixture(t, role, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				sends.Add(1)
				port := "9444"
				if role == "writer" {
					port = "9443"
				}
				if r.Host != net.JoinHostPort(f.config.Floor.NativeIPv4, port) || r.URL.Path != "/rpc/execute" || r.Method != http.MethodPost || r.URL.RawQuery != "" || r.Header.Get("Authorization") != "" || r.TLS == nil || len(r.TLS.VerifiedChains) != 1 {
					t.Error("protected destination or actual client authentication changed")
				}
				raw, e := io.ReadAll(r.Body)
				if e != nil {
					t.Error(e)
				}
				members, e := NativeCanonicalObject(raw, map[string]bool{"operation": true, "capability": true, "input": true})
				if e != nil || len(members) != 3 {
					t.Error("not the real System three-field envelope")
				}
				var req struct {
					Operation  string          `json:"operation"`
					Capability string          `json:"capability"`
					Input      json.RawMessage `json:"input"`
				}
				if DecodeNativeCapacity(json.RawMessage(raw), &req) != nil || req.Capability != req.Operation {
					t.Error("invalid operation envelope")
				}
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("X-Yggdrasil-Source-Commit", f.config.SystemSourceCommit)
				var out any
				if role == "reader" {
					var in model.CapacityNativeWorkerNetworkObserveInput
					if nativeWorkerNetworkRPCDecode(req.Input, &in) != nil || in != f.selector {
						t.Error("reader selectors changed")
					}
					out = nativeFloorRPCObservation(f.config, in)
				} else {
					var in model.CapacityNativeWorkerNetworkMutationInput
					if nativeWorkerNetworkRPCDecode(req.Input, &in) != nil || in.BindingName != f.config.BindingName {
						t.Error("mutation acquired caller-selected parameters")
					}
					out = NativeWorkerNetworkRPCMutationResult{PermitID: in.PermitID, State: "unknown", GetOnlyRecovery: true}
				}
				_, _ = w.Write(nativeFloorRPCReply(req.Operation, out))
			}))
			ctx := nativeRPCTestContext(t)
			if !f.client.Matches(role, f.binding) || f.client.Matches("mixed", f.binding) {
				t.Fatal("role lost its exact binding")
			}
			if role == "reader" {
				out, e := f.client.Observe(ctx, f.selector)
				if e != nil || !out.KernelInventoryComplete || out.Interface.Present {
					t.Fatal("complete real reader response rejected or absent interface fabricated", e)
				}
				if _, e = f.client.Mutate(ctx, NativeWorkerNetworkInstall, model.CapacityNativeWorkerNetworkMutationInput{BindingName: f.config.BindingName, PermitID: uuid.NewString()}); e == nil {
					t.Fatal("reader acquired writer role")
				}
			} else {
				for _, op := range []string{NativeWorkerNetworkInstall, NativeWorkerNetworkRemove} {
					in := model.CapacityNativeWorkerNetworkMutationInput{BindingName: f.config.BindingName, PermitID: uuid.NewString()}
					out, e := f.client.Mutate(ctx, op, in)
					if e != nil || out.State != "unknown" || !out.GetOnlyRecovery || out.NetworkQualified || out.SchedulingAdmitted {
						t.Fatal("truthful unknown became effect or admission proof", e)
					}
				}
				if _, e := f.client.Observe(ctx, f.selector); e == nil {
					t.Fatal("writer acquired observer role")
				}
			}
			before := sends.Load()
			copy := *f.client
			if copy.Close() != nil || f.client.Close() != nil || f.client.Matches(role, f.binding) {
				t.Fatal("shared Close failed")
			}
			if _, e := f.client.Observe(ctx, f.selector); e == nil || sends.Load() != before {
				t.Fatal("closed copy reopened network")
			}
			for _, v := range []any{copy, &copy} {
				for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
					text := fmt.Sprintf(format, v)
					if strings.Contains(text, f.config.ClientKeyFile) || strings.Contains(text, "PRIVATE KEY") || !strings.Contains(text, "private floor network RPC client") {
						t.Fatal("opaque representation leaked")
					}
				}
				raw, _ := json.Marshal(v)
				if string(raw) != `{"private_floor_network_rpc":"redacted"}` {
					t.Fatal("private client was JSON serializable")
				}
			}
		})
	}
}

func TestNativeWorkerFloorRPCRejectsSelectionAndBindingDriftBeforeSend(t *testing.T) {
	var sends atomic.Int32
	f := newNativeFloorRPCFixture(t, "reader", http.HandlerFunc(func(http.ResponseWriter, *http.Request) { sends.Add(1) }))
	for _, fault := range []string{"binding", "attempt", "launch", "key", "floorKey", "worker", "floorAddress", "prefixAddress", "outside", "noDeadline", "cancelled", "longDeadline"} {
		t.Run(fault, func(t *testing.T) {
			in, ctx := f.selector, nativeRPCTestContext(t)
			switch fault {
			case "binding":
				in.BindingName = "foreign"
			case "attempt":
				in.AttemptID = "not-uuid"
			case "launch":
				in.LaunchSHA256 = strings.Repeat("A", 64)
			case "key":
				in.WorkerPublicKey = "invalid"
			case "floorKey":
				in.WorkerPublicKey = f.config.Template.FloorPublicKey
			case "worker":
				in.WorkerIPv4 = "::ffff:10.90.0.2"
			case "floorAddress":
				in.WorkerIPv4 = f.config.Template.FloorPeerIPv4
			case "prefixAddress":
				in.WorkerIPv4 = "10.90.0.0"
			case "outside":
				in.WorkerIPv4 = "10.91.0.2"
			case "noDeadline":
				ctx = t.Context()
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "longDeadline":
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(t.Context(), 100*time.Second)
				defer cancel()
			}
			if _, e := f.client.Observe(ctx, in); e == nil {
				t.Fatal("unbound selector accepted")
			}
		})
	}
	for _, fault := range []string{"scope", "source", "binding", "adapter", "floor", "template", "templateHash", "role"} {
		b := f.binding
		role := "reader"
		switch fault {
		case "scope":
			b.Reader.ScopeSHA256 = strings.Repeat("f", 64)
		case "source":
			b.Reader.SystemSourceCommit = strings.Repeat("f", 40)
		case "binding":
			b.Reader.BindingName = "foreign"
		case "adapter":
			b.Reader.AdapterID = uuid.NewString()
		case "floor":
			b.Floor.NativeIPv4 = "10.70.1.3"
		case "template":
			b.Template.MTU = 1500
		case "templateHash":
			b.TemplateSHA256 = strings.Repeat("f", 64)
		case "role":
			role = "writer"
		}
		if f.client.Matches(role, b) {
			t.Fatal("substituted Source/scope/identity accepted", fault)
		}
	}
	if sends.Load() != 0 {
		t.Fatal("invalid input performed TLS RPC")
	}
}

func TestNativeWorkerFloorRPCWriterKeepsConsumedDispositionsWithoutNewEffectClaims(t *testing.T) {
	var f nativeFloorRPCFixture
	var sends atomic.Int32
	var state atomic.Value
	state.Store("unknown")
	permit := uuid.NewString()
	f = newNativeFloorRPCFixture(t, "writer", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sends.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Yggdrasil-Source-Commit", f.config.SystemSourceCommit)
		_, _ = w.Write(nativeFloorRPCReply(NativeWorkerNetworkInstall, NativeWorkerNetworkRPCMutationResult{PermitID: permit, State: state.Load().(string), GetOnlyRecovery: true}))
	}))
	ctx := nativeRPCTestContext(t)
	in := model.CapacityNativeWorkerNetworkMutationInput{BindingName: f.config.BindingName, PermitID: permit}
	for _, invalid := range []struct {
		operation string
		input     model.CapacityNativeWorkerNetworkMutationInput
	}{
		{"destroy_everything", in},
		{ObserveNativeWorkerNetwork, in},
		{NativeWorkerNetworkInstall, model.CapacityNativeWorkerNetworkMutationInput{BindingName: "foreign", PermitID: permit}},
		{NativeWorkerNetworkRemove, model.CapacityNativeWorkerNetworkMutationInput{BindingName: f.config.BindingName, PermitID: "not-a-uuid"}},
	} {
		if _, err := f.client.Mutate(ctx, invalid.operation, invalid.input); err == nil || sends.Load() != 0 {
			t.Fatal("invalid writer selectors reached the network")
		}
	}
	for _, next := range []string{"issued", "redeemed", "received", "unknown", "no_effect", "observed", "original_return_custodied"} {
		state.Store(next)
		out, err := f.client.Mutate(ctx, NativeWorkerNetworkInstall, in)
		if err != nil || out.State != next || out.PermitID != permit || !out.GetOnlyRecovery || out.NetworkQualified || out.SchedulingAdmitted {
			t.Fatal("original System disposition became effect or admission proof", err, next)
		}
	}
	if sends.Load() != 7 {
		t.Fatal("a single requested disposition caused a replay", sends.Load())
	}
}

func TestNativeWorkerFloorRPCClosedReplyAndExplicitFalseFields(t *testing.T) {
	for _, role := range []string{"reader", "writer"} {
		t.Run(role, func(t *testing.T) {
			faults := []string{"missingMetadata", "metadataNull", "missingFalse", "falseNull", "metadataAlias", "metadataExtra", "permissionTrue", "extraEnvelope", "aliasEnvelope", "duplicateEnvelope", "wrongOperation", "wrongCapability", "wrongStatus", "nullOutput", "extraPrivateOutput", "duplicateOutput", "missingOutputField", "nullOutputField", "foreignBindingOrPermit", "foreignScopeOrState", "foreignFloorOrFlag", "nullArrayOrRecovery", "staleOrFuture", "sourceMissing", "sourceDuplicate", "sourceWrong", "redirect", "overflow"}
			if role == "reader" {
				faults = append(faults, "emptyInterface", "foreignInterface")
			}
			for _, fault := range faults {
				t.Run(fault, func(t *testing.T) {
					var f nativeFloorRPCFixture
					var sends atomic.Int32
					permit := uuid.NewString()
					f = newNativeFloorRPCFixture(t, role, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						sends.Add(1)
						op := ObserveNativeWorkerNetwork
						var output any = nativeFloorRPCObservation(f.config, f.selector)
						if role == "writer" {
							op = NativeWorkerNetworkInstall
							output = NativeWorkerNetworkRPCMutationResult{PermitID: permit, State: "original_return_custodied", GetOnlyRecovery: true}
						}
						raw := nativeFloorRPCReply(op, output)
						var env map[string]json.RawMessage
						_ = json.Unmarshal(raw, &env)
						var meta map[string]any
						_ = json.Unmarshal(env["metadata"], &meta)
						var out map[string]any
						_ = json.Unmarshal(env["output"], &out)
						switch fault {
						case "missingMetadata":
							delete(env, "metadata")
						case "metadataNull":
							env["metadata"] = json.RawMessage("null")
						case "missingFalse":
							delete(meta, "network_admission_qualified")
						case "falseNull":
							meta["network_admission_qualified"] = nil
						case "metadataAlias":
							delete(meta, "useful_capacity_qualified")
							meta["Useful_capacity_qualified"] = false
						case "metadataExtra":
							meta["original_return"] = false
						case "permissionTrue":
							meta["useful_capacity_qualified"] = true
						case "extraEnvelope":
							env["auth"] = json.RawMessage(`{"private":"must-not-leak"}`)
						case "aliasEnvelope":
							env["Operation"] = env["operation"]
							delete(env, "operation")
						case "wrongOperation":
							env["operation"] = json.RawMessage(`"destroy_everything"`)
						case "wrongCapability":
							env["capability"] = json.RawMessage(`"observe_other"`)
						case "wrongStatus":
							env["status"] = json.RawMessage(`"success"`)
						case "nullOutput":
							env["output"] = json.RawMessage("null")
						case "emptyInterface":
							out["interface"].(map[string]any)["name"] = ""
						case "foreignInterface":
							out["interface"].(map[string]any)["name"] = "wg-foreign"
						case "extraPrivateOutput":
							out["original_return"] = base64.StdEncoding.EncodeToString([]byte("private-original"))
						case "missingOutputField":
							if role == "reader" {
								delete(out, "kernel_settings")
							} else {
								delete(out, "network_qualified")
							}
						case "nullOutputField":
							if role == "reader" {
								out["kernel_settings"] = nil
							} else {
								out["network_qualified"] = nil
							}
						case "foreignBindingOrPermit":
							if role == "reader" {
								out["binding_name"] = "foreign"
							} else {
								out["permit_id"] = uuid.NewString()
							}
						case "foreignScopeOrState":
							if role == "reader" {
								out["reader_scope_sha256"] = strings.Repeat("f", 64)
							} else {
								out["state"] = "admitted"
							}
						case "foreignFloorOrFlag":
							if role == "reader" {
								out["floor"].(map[string]any)["bound"].(map[string]any)["node_uid"] = uuid.NewString()
							} else {
								out["network_qualified"] = true
							}
						case "nullArrayOrRecovery":
							if role == "reader" {
								out["peers"] = nil
							} else {
								out["get_only_recovery"] = false
							}
						case "staleOrFuture":
							if role == "reader" {
								out["observed_at"] = time.Now().Add(time.Minute)
							} else {
								out["scheduling_admitted"] = true
							}
						}
						if strings.HasPrefix(fault, "metadata") || fault == "missingFalse" || fault == "falseNull" || fault == "permissionTrue" {
							if fault != "metadataNull" {
								env["metadata"], _ = json.Marshal(meta)
							}
						}
						switch fault {
						case "emptyInterface", "foreignInterface", "extraPrivateOutput", "missingOutputField", "nullOutputField", "foreignBindingOrPermit", "foreignScopeOrState", "foreignFloorOrFlag", "nullArrayOrRecovery", "staleOrFuture":
							env["output"], _ = json.Marshal(out)
						}
						raw, _ = json.Marshal(env)
						if fault == "duplicateEnvelope" {
							raw = bytes.Replace(raw, []byte(`"operation":`), []byte(`"operation":"bad","operation":`), 1)
						}
						if fault == "duplicateOutput" {
							key := `"permit_id":`
							if role == "reader" {
								key = `"binding_name":`
							}
							raw = bytes.Replace(raw, []byte(key), []byte(key+`"duplicate",`+key), 1)
						}
						w.Header().Set("Content-Type", "application/json")
						w.Header().Set("X-Yggdrasil-Source-Commit", f.config.SystemSourceCommit)
						switch fault {
						case "sourceMissing":
							w.Header().Del("X-Yggdrasil-Source-Commit")
						case "sourceDuplicate":
							w.Header().Add("X-Yggdrasil-Source-Commit", f.config.SystemSourceCommit)
						case "sourceWrong":
							w.Header().Set("X-Yggdrasil-Source-Commit", strings.Repeat("f", 40))
						case "redirect":
							http.Redirect(w, r, "https://foreign.invalid/rpc/execute", http.StatusTemporaryRedirect)
							return
						case "overflow":
							raw = []byte(strings.Repeat("x", (2<<20)+1))
						}
						_, _ = w.Write(raw)
					}))
					var err error
					if role == "reader" {
						_, err = f.client.Observe(nativeRPCTestContext(t), f.selector)
					} else {
						_, err = f.client.Mutate(nativeRPCTestContext(t), NativeWorkerNetworkInstall, model.CapacityNativeWorkerNetworkMutationInput{BindingName: f.config.BindingName, PermitID: permit})
					}
					if err == nil || sends.Load() != 1 || strings.Contains(fmt.Sprint(err), "private-original") || strings.Contains(fmt.Sprint(err), "foreign.invalid") {
						t.Fatal("unqualified reply accepted, retried or disclosed", err, sends.Load())
					}
				})
			}
		})
	}
}

type nativeFloorRPCBody struct {
	io.ReadCloser
	closeCount *atomic.Int32
	failRead   bool
	failClose  bool
	cancel     context.CancelFunc
}

func (b nativeFloorRPCBody) Read(p []byte) (int, error) {
	if b.failRead {
		return 0, errors.New("private read failure")
	}
	return b.ReadCloser.Read(p)
}
func (b nativeFloorRPCBody) Close() error {
	b.closeCount.Add(1)
	err := b.ReadCloser.Close()
	if b.cancel != nil {
		b.cancel()
	}
	if b.failClose {
		return errors.Join(err, errors.New("private close failure"))
	}
	return err
}

func TestNativeWorkerFloorRPCActualTLSOriginalReadCloseAndCancellationAreMandatory(t *testing.T) {
	for _, fault := range []string{"read", "close", "cancel"} {
		t.Run(fault, func(t *testing.T) {
			var f nativeFloorRPCFixture
			var sends, closed atomic.Int32
			f = newNativeFloorRPCFixture(t, "reader", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				sends.Add(1)
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("X-Yggdrasil-Source-Commit", f.config.SystemSourceCommit)
				_, _ = w.Write(nativeFloorRPCReply(ObserveNativeWorkerNetwork, nativeFloorRPCObservation(f.config, f.selector)))
			}))
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			original := f.client.client.Transport
			f.client.client.Transport = nativeRPCRoundTripFunc(func(r *http.Request) (*http.Response, error) {
				if r.GetBody != nil {
					t.Error("original send became replayable")
				}
				reply, err := original.RoundTrip(r)
				if reply != nil && reply.Body != nil {
					body := nativeFloorRPCBody{ReadCloser: reply.Body, closeCount: &closed, failRead: fault == "read", failClose: fault == "close"}
					if fault == "cancel" {
						body.cancel = cancel
					}
					reply.Body = body
				}
				return reply, err
			})
			if _, err := f.client.Observe(ctx, f.selector); err == nil || sends.Load() != 1 || closed.Load() != 1 || strings.Contains(fmt.Sprint(err), "private ") {
				t.Fatal("original transport failure became complete or replayed", err, sends.Load(), closed.Load())
			}
		})
	}
}

func TestNativeWorkerFloorRPCProtectedTrustHostnameRoleAndFilesCannotBeSubstituted(t *testing.T) {
	for _, fault := range []string{"role", "identity", "source", "scope", "nativePublic", "nativeAlias", "template", "keyMode", "keySymlink", "caHash", "clientPurpose", "serverPin", "untrustedCA", "wrongHostname"} {
		t.Run(fault, func(t *testing.T) {
			var sends atomic.Int32
			certificateIP := "10.70.1.2"
			if fault == "wrongHostname" {
				certificateIP = "10.70.1.3"
			}
			f := newNativeFloorRPCFixture(t, "reader", http.HandlerFunc(func(http.ResponseWriter, *http.Request) { sends.Add(1) }), certificateIP)
			c := f.config
			postConstructor := false
			switch fault {
			case "role":
				c.Role = "reader,writer"
			case "identity":
				c.AdapterID = "not-an-adapter"
			case "source":
				c.SystemSourceCommit = strings.Repeat("C", 40)
			case "scope":
				c.ScopeSHA256 = "binding-reencoding"
			case "nativePublic":
				c.Floor.NativeIPv4 = "8.8.8.8"
			case "nativeAlias":
				c.Floor.NativeIPv4 = "floor.invalid"
			case "template":
				c.Template.PodCIDR = c.Template.TransportCIDR
				c.TemplateSHA256 = NativeWorkerNetworkTemplateSHA256(c.Template)
			case "keyMode":
				if e := os.Chmod(c.ClientKeyFile, 0644); e != nil {
					t.Fatal(e)
				}
			case "keySymlink":
				path := c.ClientKeyFile + ".link"
				if e := os.Symlink(c.ClientKeyFile, path); e != nil {
					t.Fatal(e)
				}
				c.ClientKeyFile = path
			case "caHash":
				c.ServerCASHA256 = strings.Repeat("f", 64)
			case "clientPurpose":
				pki := nativeRPCPKI(t)
				_, cert, key := pki.leaf(t, x509.ExtKeyUsageServerAuth)
				if os.WriteFile(c.ClientCertificateFile, cert, 0600) != nil || os.WriteFile(c.ClientKeyFile, key, 0600) != nil {
					t.Fatal("CI certificate replacement failed")
				}
			case "serverPin":
				c.ServerCertificateSHA256 = strings.Repeat("f", 64)
				postConstructor = true
			case "untrustedCA":
				pki := nativeRPCPKI(t)
				if e := os.WriteFile(c.ServerCAFile, pki.caPEM, 0600); e != nil {
					t.Fatal(e)
				}
				c.ServerCASHA256 = nativeRPCHash(pki.caPEM)
				postConstructor = true
			case "wrongHostname":
				postConstructor = true
			}
			client, err := newNativeWorkerNetworkRPCClient(c, f.dial)
			if postConstructor {
				if err != nil {
					t.Fatal("valid protected config should reach actual TLS refusal", err)
				}
				defer client.Close()
				if _, err = client.Observe(nativeRPCTestContext(t), f.selector); err == nil {
					t.Fatal("untrusted/foreign TLS peer accepted")
				}
			} else if err == nil {
				_ = client.Close()
				t.Fatal("unsafe protected configuration accepted")
			}
			if sends.Load() != 0 {
				t.Fatal("request body reached unauthenticated or unbound server")
			}
		})
	}
}
