package httpapi

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

const memberListenerTestPermitID = "12345678-1234-4234-8234-123456789abc"
const memberListenerTestReadID = "12345678-1234-4234-8234-123456789abd"
const memberListenerStockPath = "/internal/capacity/native-workers/native-scheduler/bind"
const memberListenerPrivateDiagnostic = "private-member-backend-diagnostic"
const memberListenerPrivateOriginal = "private-configz-or-effect-original"

// Source mirror of upstream v1.34.6 ExtenderBindingArgs: the official fields
// have NO JSON tags. scheduler/extender.go marshals that struct directly, so
// this peer request is deliberately independent of the product's wire mirror.
type memberListenerUpstreamExtenderBindingArgs struct {
	PodName      string
	PodNamespace string
	PodUID       string
	Node         string
}

// Transport fixtures only: these callbacks do not implement journal authority,
// Kubernetes effects, independent evidence, a scheduler or production readiness.
type memberListenerBackendFixture struct {
	mu                 sync.Mutex
	config             NativeWorkerMemberListenerConfig
	calls              map[string]int
	variant            string
	fail, ignoreCancel bool
	entered            chan struct{}
	release            <-chan struct{}
	received           model.CapacityNativeWorkerMemberReceive
	readOriginal       model.CapacityNativeWorkerMemberReadOriginal
	binding            NativeWorkerSchedulerBinding
}

func (b *memberListenerBackendFixture) touch(ctx context.Context, action string) error {
	b.mu.Lock()
	b.calls[action]++
	fail, entered, release, ignore := b.fail, b.entered, b.release, b.ignoreCancel
	b.mu.Unlock()
	if action == "read" && entered != nil {
		close(entered)
		if ignore {
			<-release
		} else {
			select {
			case <-release:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
	if fail {
		return errors.New(memberListenerPrivateDiagnostic)
	}
	return nil
}
func (b *memberListenerBackendFixture) count() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := 0
	for _, v := range b.calls {
		n += v
	}
	return n
}
func (b *memberListenerBackendFixture) context(in model.CapacityNativeWorkerMemberSelectors) model.CapacityNativeWorkerMemberContext {
	c := b.config.Transport
	actor := model.CapacityNativeWorkerMemberEndpoint{BindingName: c.BindingName, SourceCommit: c.SDKSourceCommit, ScopeSHA256: c.SDKScopeSHA256, Capability: "ensure_native_worker_pool_member"}
	observer := actor
	observer.Capability = "observe_native_worker_pool_member"
	// Controller identity owns reconciliation, not the SDK actor/observer.
	if b.config.Role == "member_controller" {
		actor.SourceCommit = strings.Repeat("b", 40)
		actor.ScopeSHA256 = strings.Repeat("c", 64)
		observer = actor
		observer.Capability = "observe_native_worker_pool_member"
	}
	return model.CapacityNativeWorkerMemberContext{
		Schema:   model.CapacityNativeWorkerMemberContextSchema,
		PermitID: in.PermitID, PlanID: "12345678-1234-4234-8234-123456789abe",
		AttemptID: "12345678-1234-4234-8234-123456789abf", CoreSourceCommit: c.CoreSourceCommit,
		Mode: "never_admitted", Action: "cordon", Actor: actor, Observer: observer, NotAfter: time.Now().UTC().Add(30 * time.Second),
		Node: &model.CapacityNativeWorkerMemberNode{Name: "nw-ci-member", UID: "opaque-node-uid", ResourceVersion: "opaque-node-rv"},
	}
}
func (b *memberListenerBackendFixture) Read(ctx context.Context, in model.CapacityNativeWorkerMemberSelectors) (model.CapacityNativeWorkerMemberRead, error) {
	err := b.touch(ctx, "read")
	out := model.CapacityNativeWorkerMemberRead{Schema: model.CapacityNativeWorkerMemberReadSchema, BindingName: in.BindingName, Context: b.context(in), State: "issued"}
	if b.config.Role == "kube_member_writer" {
		out.Redeemable = true
	} else {
		out.ReadID = memberListenerTestReadID
	}
	b.mu.Lock()
	variant := b.variant
	b.mu.Unlock()
	switch variant {
	case "read_id_empty":
		out.ReadID = ""
	case "read_id_alias":
		out.ReadID = strings.ToUpper(memberListenerTestReadID)
	case "reader_grant":
		out.Redeemable = true
	case "reader_mutation":
		out.MutationPermitted = true
	case "binding":
		out.BindingName = "foreign"
	case "permit":
		out.Context.PermitID = "12345678-1234-4234-8234-123456789aaa"
	case "core_source":
		out.Context.CoreSourceCommit = strings.Repeat("d", 40)
	case "endpoint_binding":
		out.Context.Actor.BindingName = "foreign"
		out.Context.Observer.BindingName = "foreign"
	case "endpoint_source":
		out.Context.Actor.SourceCommit = strings.Repeat("d", 40)
		out.Context.Observer.SourceCommit = strings.Repeat("d", 40)
	case "endpoint_scope":
		out.Context.Actor.ScopeSHA256 = strings.Repeat("d", 64)
		out.Context.Observer.ScopeSHA256 = strings.Repeat("d", 64)
	}
	return out, err
}
func (b *memberListenerBackendFixture) ReadAllocatorFence(ctx context.Context, in model.CapacityNativeWorkerMemberSelectors) (model.CapacityNativeWorkerAllocatorFenceRead, error) {
	err := b.touch(ctx, "fence")
	c := b.config.Transport
	out := model.CapacityNativeWorkerAllocatorFenceRead{Schema: model.CapacityNativeWorkerAllocatorFenceReadSchema, BindingName: in.BindingName, Context: model.CapacityNativeWorkerAllocatorFenceContext{Schema: model.CapacityNativeWorkerAllocatorFenceContextSchema, CreatorPermitID: in.PermitID, CoreSourceCommit: c.CoreSourceCommit, Observer: model.CapacityNativeWorkerMemberEndpoint{BindingName: c.BindingName, SourceCommit: c.SDKSourceCommit, ScopeSHA256: c.SDKScopeSHA256, Capability: "observe_native_worker_allocator_fence"}, NotAfter: time.Now().UTC().Add(30 * time.Second)}}
	b.mu.Lock()
	variant := b.variant
	b.mu.Unlock()
	if variant == "fence_capability" {
		out.Context.Observer.Capability = "ensure_native_worker_pool_member"
	}
	return out, err
}
func (b *memberListenerBackendFixture) Redeem(ctx context.Context, in model.CapacityNativeWorkerMemberSelectors) (model.CapacityNativeWorkerMemberPermit, error) {
	if err := b.touch(ctx, "redeem"); err != nil {
		return model.CapacityNativeWorkerMemberPermit{}, err
	}
	return model.NewCapacityNativeWorkerMemberPermit(b.context(in), base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)))
}
func (b *memberListenerBackendFixture) Receive(ctx context.Context, in model.CapacityNativeWorkerMemberReceive) error {
	if err := b.touch(ctx, "receive"); err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.received = in
	b.received.OriginalReturn = bytes.Clone(in.OriginalReturn)
	return nil
}
func (b *memberListenerBackendFixture) ReceiveRead(ctx context.Context, in model.CapacityNativeWorkerMemberReadOriginal) error {
	if err := b.touch(ctx, "receive-read"); err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.readOriginal = in
	b.readOriginal.OriginalReturn = bytes.Clone(in.OriginalReturn)
	return nil
}
func (b *memberListenerBackendFixture) Reconcile(ctx context.Context, in model.CapacityNativeWorkerMemberSelectors) (model.CapacityNativeWorkerMemberRead, error) {
	if err := b.touch(ctx, "reconcile"); err != nil {
		return model.CapacityNativeWorkerMemberRead{}, err
	}
	out := model.CapacityNativeWorkerMemberRead{Schema: model.CapacityNativeWorkerMemberReadSchema, BindingName: in.BindingName, Context: b.context(in), State: "unknown"}
	b.mu.Lock()
	variant := b.variant
	b.mu.Unlock()
	if variant == "controller_grant" {
		out.Redeemable = true
	}
	if variant == "controller_mutation" {
		out.MutationPermitted = true
	}
	return out, nil
}
func (b *memberListenerBackendFixture) Bind(ctx context.Context, in NativeWorkerSchedulerBinding) error {
	if err := b.touch(ctx, "bind"); err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.binding = in
	return nil
}
func memberListenerNew(t *testing.T, role string) (*NativeWorkerMemberListener, *memberListenerBackendFixture, nativeProbeListenerTLSFixture) {
	t.Helper()
	f := nativeProbeListenerTLS(t)
	f.config.BindingName = "source-owned-member"
	c := NativeWorkerMemberListenerConfig{Role: role, Transport: f.config}
	if role == "member_controller" {
		c.Transport.SDKSourceCommit = nativeProbeListenerTestSource
	}
	if role == "stock_scheduler" {
		c.Transport.SDKSourceCommit = ""
		c.Transport.SDKScopeSHA256 = ""
		c.Transport.BearerTokenSHA256 = ""
		c.StockProfileSourceCommit = strings.Repeat("e", 40)
		c.StockProfileSHA256 = strings.Repeat("f", 64)
	}
	b := &memberListenerBackendFixture{config: c, calls: map[string]int{}}
	l, err := newNativeWorkerMemberListener(c, b, nativeProbeListenerTestSource)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := l.Close(); err != nil {
			t.Error("private member listener did not join")
		}
	})
	return l, b, f
}
func memberListenerSelectors() model.CapacityNativeWorkerMemberSelectors {
	return model.CapacityNativeWorkerMemberSelectors{BindingName: "source-owned-member", PermitID: memberListenerTestPermitID}
}
func memberListenerBody(t *testing.T, action string) []byte {
	t.Helper()
	in := memberListenerSelectors()
	switch action {
	case "read":
		return nil
	case "receive":
		out := model.CapacityNativeWorkerMemberReceive{Schema: model.CapacityNativeWorkerMemberReceiveSchema, BindingName: in.BindingName, PermitID: in.PermitID, SettlementToken: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)), HTTPStatus: 409, OriginalReturn: []byte(memberListenerPrivateOriginal), CaptureComplete: true, TransportCompleted: true, CompletedAt: time.Now().UTC()}
		raw, err := out.PrivateJSON()
		if err != nil {
			t.Fatal(err)
		}
		return raw
	case "receive-read":
		out := model.CapacityNativeWorkerMemberReadOriginal{Schema: model.CapacityNativeWorkerMemberReadOriginalSchema, BindingName: in.BindingName, PermitID: in.PermitID, ReadID: memberListenerTestReadID, Kind: "kubelet_configz", HTTPStatus: 200, OriginalReturn: []byte(memberListenerPrivateOriginal), CaptureComplete: true, TransportCompleted: true, CompletedAt: time.Now().UTC()}
		raw, err := out.PrivateJSON()
		if err != nil {
			t.Fatal(err)
		}
		return raw
	case "bind":
		raw, err := json.Marshal(memberListenerUpstreamExtenderBindingArgs{PodName: "nw-ci-pod", PodNamespace: "ci-native", PodUID: memberListenerTestPermitID, Node: "nw-ci-node"})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	default:
		raw, err := json.Marshal(in)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
}
func memberListenerRequest(t *testing.T, address string, b *memberListenerBackendFixture, action string, raw []byte) *http.Request {
	t.Helper()
	method, path := http.MethodPost, model.CapacityNativeWorkerMemberCallbackBase+action
	if action == "bind" {
		path = memberListenerStockPath
	}
	if action == "read" {
		method = http.MethodGet
		in := memberListenerSelectors()
		path += "?" + url.Values{"binding_name": {in.BindingName}, "permit_id": {in.PermitID}}.Encode()
	}
	r, err := http.NewRequest(method, "https://"+address+path, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if b.config.Role != "stock_scheduler" {
		r.Header.Set("Authorization", "Bearer "+nativeProbeListenerTestToken)
		r.Header.Set(nativeWorkerPhaseAdapterSourceHeader, b.config.Transport.SDKSourceCommit)
		r.Header.Set(nativeProbeResourceScopeHeader, b.config.Transport.SDKScopeSHA256)
	}
	return r
}
func memberListenerResponse(t *testing.T, client *http.Client, r *http.Request) (int, []byte) {
	t.Helper()
	out, err := client.Do(r)
	if err != nil {
		t.Fatal("actual member TLS callback failed", err)
	}
	raw, re := io.ReadAll(out.Body)
	ce := out.Body.Close()
	if re != nil || ce != nil || len(out.Header.Values("X-Yggdrasil-Source-Commit")) != 1 || out.Header.Get("X-Yggdrasil-Source-Commit") != nativeProbeListenerTestSource || out.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("member response original Source/Close framing", re, ce)
	}
	if bytes.Contains(raw, []byte(memberListenerPrivateDiagnostic)) {
		t.Fatal("private backend diagnostic escaped")
	}
	return out.StatusCode, raw
}
func memberListenerNoPrivate(t *testing.T, raw []byte) {
	t.Helper()
	for _, secret := range []string{memberListenerPrivateOriginal, base64.StdEncoding.EncodeToString([]byte(memberListenerPrivateOriginal)), base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)), "settlement_token", "original_return", "raw_sha256", "bootstrap_token", "bootstrap_body"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatal("non-redeem response exposed private wire material")
		}
	}
}

func TestNativeMemberListenerFiveRolesSevenCallbacksRealTLS(t *testing.T) {
	allowed := map[string]map[string]int{
		"kube_member_writer":          {"read": 200, "redeem": 200, "receive": 204},
		"kube_member_reader":          {"read": 200, "receive-read": 204},
		"kube_allocator_fence_reader": {"read": 200},
		"member_controller":           {"reconcile": 200},
		"stock_scheduler":             {"bind": 200},
	}
	for role, routes := range allowed {
		t.Run(role, func(t *testing.T) {
			l, b, f := memberListenerNew(t, role)
			if err := l.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			client := nativeProbeListenerClient(t, f, &f.client)
			for _, action := range []string{"read", "redeem", "receive", "receive-read", "reconcile", "bind"} {
				before := b.count()
				status, raw := memberListenerResponse(t, client, memberListenerRequest(t, l.Address(), b, action, memberListenerBody(t, action)))
				want, ok := routes[action]
				if !ok {
					if status >= 200 && status < 300 || b.count() != before {
						t.Fatal("role crossed fixed callback boundary", role, action, status)
					}
					memberListenerNoPrivate(t, raw)
					continue
				}
				if status != want || b.count() != before+1 {
					t.Fatal("allowed role callback not delivered once", role, action, status)
				}
				if action == "redeem" {
					var wire struct {
						Schema            string `json:"schema"`
						State             string `json:"state"`
						MutationPermitted bool   `json:"mutation_permitted"`
						SettlementToken   string `json:"settlement_token"`
					}
					if json.Unmarshal(raw, &wire) != nil || wire.Schema != model.CapacityNativeWorkerMemberPermitSchema || wire.State != "redeemed" || !wire.MutationPermitted || wire.SettlementToken != base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)) {
						t.Fatal("opaque redeem did not use explicit private wire")
					}
				} else {
					memberListenerNoPrivate(t, raw)
				}
				if action == "read" && role == "kube_allocator_fence_reader" {
					var out model.CapacityNativeWorkerAllocatorFenceRead
					if json.Unmarshal(raw, &out) != nil || out.Schema != model.CapacityNativeWorkerAllocatorFenceReadSchema || out.Context.Observer.Capability != "observe_native_worker_allocator_fence" {
						t.Fatal("fence role used member read shape")
					}
				}
				if action == "bind" {
					var out map[string]json.RawMessage
					if json.Unmarshal(raw, &out) != nil || len(out) != 1 || string(out["Error"]) != `""` {
						t.Fatal("stock success is not official binding result")
					}
				}
			}
			b.mu.Lock()
			received, readOriginal := b.received, b.readOriginal
			b.mu.Unlock()
			if role == "kube_member_writer" && string(received.OriginalReturn) != memberListenerPrivateOriginal {
				t.Fatal("writer original was not delivered privately")
			}
			if role == "kube_member_reader" && (readOriginal.ReadID != memberListenerTestReadID || string(readOriginal.OriginalReturn) != memberListenerPrivateOriginal) {
				t.Fatal("read-only custody lost pre-issued ReadID/original")
			}
		})
	}
}

func memberListenerDirect(t *testing.T, b *memberListenerBackendFixture, f nativeProbeListenerTLSFixture, action string, body io.ReadCloser) *http.Request {
	t.Helper()
	r := memberListenerRequest(t, "127.0.0.1:9447", b, action, nil)
	r.Body = body
	r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, PeerCertificates: []*x509.Certificate{f.client.Leaf}, VerifiedChains: [][]*x509.Certificate{{f.client.Leaf}}}
	return r
}
func memberListenerRecordedSource(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	if len(w.Header().Values("X-Yggdrasil-Source-Commit")) != 1 || w.Header().Get("X-Yggdrasil-Source-Commit") != nativeProbeListenerTestSource || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("refusal lost exact compiled Source/no-store")
	}
}
func TestNativeMemberListenerPrebodyAuthenticationAndDedicatedRoles(t *testing.T) {
	for _, role := range []string{"kube_member_writer", "kube_member_reader", "kube_allocator_fence_reader", "member_controller", "stock_scheduler"} {
		t.Run(role, func(t *testing.T) {
			l, b, f := memberListenerNew(t, role)
			action := "read"
			if role == "kube_member_writer" {
				action = "redeem"
			}
			if role == "member_controller" {
				action = "reconcile"
			}
			if role == "stock_scheduler" {
				action = "bind"
			}
			changes := []struct {
				name   string
				change func(*http.Request)
			}{
				{"unverified", func(r *http.Request) { r.TLS.VerifiedChains = nil }},
				{"wrong_leaf", func(r *http.Request) { r.TLS.PeerCertificates = []*x509.Certificate{f.wrongLeaf.Leaf} }},
			}
			for _, header := range []string{"Authorization", nativeWorkerPhaseAdapterSourceHeader, nativeProbeResourceScopeHeader} {
				h := header
				if role == "stock_scheduler" {
					changes = append(changes, struct {
						name   string
						change func(*http.Request)
					}{"unexpected_" + h, func(r *http.Request) { r.Header.Add(h, "") }})
				} else {
					changes = append(changes, struct {
						name   string
						change func(*http.Request)
					}{"wrong_" + h, func(r *http.Request) { r.Header.Set(h, "foreign") }})
					changes = append(changes, struct {
						name   string
						change func(*http.Request)
					}{"duplicate_" + h, func(r *http.Request) { r.Header.Add(h, r.Header.Get(h)) }})
				}
			}
			for _, item := range changes {
				t.Run(item.name, func(t *testing.T) {
					body := &nativeProbeListenerRequestBody{raw: []byte(memberListenerPrivateOriginal)}
					r := memberListenerDirect(t, b, f, action, body)
					item.change(r)
					w := httptest.NewRecorder()
					l.state.handle(w, r)
					memberListenerRecordedSource(t, w)
					if w.Code != http.StatusForbidden || body.reads != 0 || body.closes != 0 || b.count() != 0 {
						t.Fatal("identity refusal consumed body or backend", w.Code, body.reads, body.closes)
					}
					memberListenerNoPrivate(t, w.Body.Bytes())
				})
			}
			denied := "redeem"
			if role == "kube_member_writer" {
				denied = "receive-read"
			}
			body := &nativeProbeListenerRequestBody{raw: []byte(memberListenerPrivateOriginal)}
			w := httptest.NewRecorder()
			l.state.handle(w, memberListenerDirect(t, b, f, denied, body))
			memberListenerRecordedSource(t, w)
			if w.Code >= 200 && w.Code < 300 || body.reads != 0 || body.closes != 0 || b.count() != 0 {
				t.Fatal("role refusal consumed private body")
			}
		})
	}
	t.Run("actual_untrusted_TLS", func(t *testing.T) {
		l, b, f := memberListenerNew(t, "kube_member_writer")
		if err := l.Start(context.Background()); err != nil {
			t.Fatal(err)
		}
		foreign := nativeProbeListenerTLS(t).client
		for _, cert := range []*tls.Certificate{nil, &foreign} {
			client := nativeProbeListenerClient(t, f, cert)
			response, err := client.Do(memberListenerRequest(t, l.Address(), b, "redeem", memberListenerBody(t, "redeem")))
			if err == nil {
				_ = response.Body.Close()
				t.Fatal("unverified TLS peer reached member HTTP")
			}
		}
		client := nativeProbeListenerClient(t, f, &f.wrongLeaf)
		status, raw := memberListenerResponse(t, client, memberListenerRequest(t, l.Address(), b, "redeem", memberListenerBody(t, "redeem")))
		if status != http.StatusForbidden || b.count() != 0 {
			t.Fatal("same-CA foreign leaf reached backend")
		}
		memberListenerNoPrivate(t, raw)
	})
}
func TestNativeMemberListenerClosedConfigurationAndRepresentations(t *testing.T) {
	l, b, f := memberListenerNew(t, "kube_member_writer")
	foreign := strings.Repeat("d", 40)
	if foreign == capacity.CurrentGuestCoreSource() {
		foreign = strings.Repeat("e", 40)
	}
	configured := b.config
	configured.Transport.CoreSourceCommit = foreign
	if got, err := NewNativeWorkerMemberListener(configured, b); err == nil {
		_ = got.Close()
		t.Fatal("public constructor trusted configured Source over compiled Source")
	}
	for _, v := range []any{l, *l, b.config, &b.config} {
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		for _, out := range []string{string(raw), fmt.Sprintf("%v %+v %#v", v, v, v)} {
			if strings.Contains(out, nativeProbeListenerTestToken) || strings.Contains(out, base64.StdEncoding.EncodeToString(f.config.ServerCertificate.Certificate[0])) || strings.Contains(out, f.config.ServerURI) {
				t.Fatal("ordinary listener representation exposed private config")
			}
		}
	}
	for _, item := range []struct {
		name   string
		change func(*NativeWorkerMemberListenerConfig)
	}{
		{"role", func(c *NativeWorkerMemberListenerConfig) { c.Role = "writer" }},
		{"core_source", func(c *NativeWorkerMemberListenerConfig) { c.Transport.CoreSourceCommit = strings.Repeat("d", 40) }},
		{"sdk_source", func(c *NativeWorkerMemberListenerConfig) { c.Transport.SDKSourceCommit = "" }},
		{"scope", func(c *NativeWorkerMemberListenerConfig) { c.Transport.SDKScopeSHA256 = "" }},
		{"bearer", func(c *NativeWorkerMemberListenerConfig) { c.Transport.BearerTokenSHA256 = "" }},
		{"mixed_profile", func(c *NativeWorkerMemberListenerConfig) {
			c.StockProfileSourceCommit = strings.Repeat("e", 40)
			c.StockProfileSHA256 = strings.Repeat("f", 64)
		}},
		{"controller_source", func(c *NativeWorkerMemberListenerConfig) { c.Role = "member_controller" }},
	} {
		t.Run(item.name, func(t *testing.T) {
			c := b.config
			item.change(&c)
			got, err := newNativeWorkerMemberListener(c, b, nativeProbeListenerTestSource)
			if err == nil {
				_ = got.Close()
				t.Fatal("invalid protected member configuration accepted")
			}
		})
	}
	stock, stockBackend, _ := memberListenerNew(t, "stock_scheduler")
	_ = stock
	for _, item := range []struct {
		name   string
		change func(*NativeWorkerMemberListenerConfig)
	}{
		{"profile_source", func(c *NativeWorkerMemberListenerConfig) { c.StockProfileSourceCommit = "" }},
		{"profile_hash", func(c *NativeWorkerMemberListenerConfig) { c.StockProfileSHA256 = "" }},
		{"dummy_sdk", func(c *NativeWorkerMemberListenerConfig) { c.Transport.SDKSourceCommit = strings.Repeat("b", 40) }},
		{"dummy_bearer", func(c *NativeWorkerMemberListenerConfig) { c.Transport.BearerTokenSHA256 = strings.Repeat("c", 64) }},
	} {
		t.Run("stock_"+item.name, func(t *testing.T) {
			c := stockBackend.config
			item.change(&c)
			got, err := newNativeWorkerMemberListener(c, stockBackend, nativeProbeListenerTestSource)
			if err == nil {
				_ = got.Close()
				t.Fatal("stock profile invented SDK identity or missed Source custody")
			}
		})
	}
	if _, err := newNativeWorkerMemberListener(b.config, (*memberListenerBackendFixture)(nil), nativeProbeListenerTestSource); err == nil {
		t.Fatal("typed nil backend accepted")
	}
	var zero NativeWorkerMemberListener
	if zero.Start(context.Background()) == nil || zero.Address() != "" || zero.Close() != nil {
		t.Fatal("zero member handle gained authority")
	}
	var absent *NativeWorkerMemberListener
	if absent.Start(context.Background()) == nil || absent.Address() != "" || absent.Close() != nil {
		t.Fatal("nil member handle gained authority")
	}
}
func TestNativeMemberListenerOriginalReadCloseAndClosedSelectors(t *testing.T) {
	l, b, f := memberListenerNew(t, "kube_member_writer")
	for _, raw := range []string{
		"[]", `{"binding_name":"source-owned-member","permit_id":"` + memberListenerTestPermitID + `","mode":"admitted"}`,
		`{"binding_name":"source-owned-member","binding_name":"source-owned-member","permit_id":"` + memberListenerTestPermitID + `"}`,
		`{"binding_name":"source-owned-member","permit_ID":"` + memberListenerTestPermitID + `"}`,
		`{"binding_name":"foreign","permit_id":"` + memberListenerTestPermitID + `"}`,
		`{"binding_name":"source-owned-member","permit_id":"00000000-0000-0000-0000-000000000000"}`,
		string(memberListenerBody(t, "redeem")) + " {}", strings.Repeat("x", model.CapacityNativeWorkerMemberMaxSelectorBytes+1),
	} {
		body := &nativeProbeListenerRequestBody{raw: []byte(raw)}
		w := httptest.NewRecorder()
		l.state.handle(w, memberListenerDirect(t, b, f, "redeem", body))
		memberListenerRecordedSource(t, w)
		if w.Code >= 200 && w.Code < 300 || body.reads == 0 || body.closes != 1 || b.count() != 0 {
			t.Fatal("non-closed selectors reached backend or bypassed original Close", w.Code)
		}
	}
	for _, mode := range []string{"read_error", "close_error", "cancel_on_close", "get_body", "get_close_error"} {
		t.Run(mode, func(t *testing.T) {
			body := &nativeProbeListenerRequestBody{raw: memberListenerBody(t, "redeem")}
			action := "redeem"
			if strings.HasPrefix(mode, "get_") {
				action = "read"
				body.raw = nil
			}
			if mode == "read_error" {
				body.readErr = errors.New("private-read-error")
			}
			if mode == "close_error" || mode == "get_close_error" {
				body.closeErr = errors.New("private-close-error")
			}
			if mode == "get_body" {
				body.raw = []byte("x")
			}
			r := memberListenerDirect(t, b, f, action, body)
			if mode == "cancel_on_close" {
				ctx, cancel := context.WithCancel(r.Context())
				defer cancel()
				r = r.WithContext(ctx)
				body.onClose = cancel
			}
			w := httptest.NewRecorder()
			l.state.handle(w, r)
			memberListenerRecordedSource(t, w)
			if w.Code >= 200 && w.Code < 300 || body.closes != 1 || b.count() != 0 {
				t.Fatal("incomplete Read+Close/context reached member backend")
			}
		})
	}
	for _, query := range []string{
		"binding_name=source-owned-member&permit_id=" + memberListenerTestPermitID + "&permit_id=" + memberListenerTestPermitID,
		"binding_name=source-owned-member&permit_id=" + strings.ToUpper(memberListenerTestPermitID),
		"binding_name=source-owned-member&permit_id=" + memberListenerTestPermitID + "&role=writer",
		"binding_name=source-owned-member&permit_ID=" + memberListenerTestPermitID,
		"binding_name=source-owned-member&permit_id=%zz",
	} {
		body := &nativeProbeListenerRequestBody{}
		r := memberListenerDirect(t, b, f, "read", body)
		r.URL.RawQuery = query
		w := httptest.NewRecorder()
		l.state.handle(w, r)
		memberListenerRecordedSource(t, w)
		if w.Code >= 200 && w.Code < 300 || body.closes != 1 || b.count() != 0 {
			t.Fatal("query alias/duplicate/free identity accepted")
		}
	}
	for _, change := range []func(*http.Request){
		func(r *http.Request) { r.Method = http.MethodPut },
		func(r *http.Request) { r.URL.Path = model.CapacityNativeWorkerMemberCallbackBase + "bootstrap" },
		func(r *http.Request) { r.URL.RawQuery = "role=writer" },
		func(r *http.Request) { r.URL.RawPath = r.URL.Path },
		func(r *http.Request) { r.URL.ForceQuery = true },
	} {
		body := &nativeProbeListenerRequestBody{raw: memberListenerBody(t, "redeem")}
		r := memberListenerDirect(t, b, f, "redeem", body)
		change(r)
		w := httptest.NewRecorder()
		l.state.handle(w, r)
		if w.Code >= 200 && w.Code < 300 || body.reads != 0 || b.count() != 0 {
			t.Fatal("unknown route/method/query read private body")
		}
	}
}

func TestNativeMemberListenerReadIDPrivateOutputAndImmutableJoins(t *testing.T) {
	for _, role := range []string{"kube_member_writer", "kube_member_reader"} {
		t.Run(role, func(t *testing.T) {
			l, b, f := memberListenerNew(t, role)
			if err := l.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			client := nativeProbeListenerClient(t, f, &f.client)
			status, raw := memberListenerResponse(t, client, memberListenerRequest(t, l.Address(), b, "read", nil))
			var out model.CapacityNativeWorkerMemberRead
			if status != http.StatusOK || json.Unmarshal(raw, &out) != nil {
				t.Fatal("closed read unavailable")
			}
			if role == "kube_member_writer" && out.ReadID != "" {
				t.Fatal("writer minted dummy read custody")
			}
			if role == "kube_member_reader" && (out.ReadID != memberListenerTestReadID || out.Redeemable || out.MutationPermitted) {
				t.Fatal("reader lost original ReadID or received grant flags")
			}
			memberListenerNoPrivate(t, raw)
			variants := []string{"binding", "permit", "core_source", "endpoint_binding", "endpoint_source", "endpoint_scope"}
			if role == "kube_member_reader" {
				variants = append(variants, "read_id_empty", "read_id_alias", "reader_grant", "reader_mutation")
			}
			for _, variant := range variants {
				b.mu.Lock()
				b.variant = variant
				b.mu.Unlock()
				status, raw = memberListenerResponse(t, client, memberListenerRequest(t, l.Address(), b, "read", nil))
				if status >= 200 && status < 300 {
					t.Fatal("read substituted immutable identity or authority", variant)
				}
				memberListenerNoPrivate(t, raw)
			}
		})
	}
	t.Run("controller_is_not_the_SDK_endpoint", func(t *testing.T) {
		l, b, f := memberListenerNew(t, "member_controller")
		if err := l.Start(context.Background()); err != nil {
			t.Fatal(err)
		}
		client := nativeProbeListenerClient(t, f, &f.client)
		status, raw := memberListenerResponse(t, client, memberListenerRequest(t, l.Address(), b, "reconcile", memberListenerBody(t, "reconcile")))
		var out model.CapacityNativeWorkerMemberRead
		if status != http.StatusOK || json.Unmarshal(raw, &out) != nil || out.Context.Actor.SourceCommit == b.config.Transport.SDKSourceCommit || out.Redeemable || out.MutationPermitted {
			t.Fatal("controller identity was confused with SDK tuple or gained grants")
		}
		for _, variant := range []string{"controller_grant", "controller_mutation"} {
			b.mu.Lock()
			b.variant = variant
			b.mu.Unlock()
			status, raw = memberListenerResponse(t, client, memberListenerRequest(t, l.Address(), b, "reconcile", memberListenerBody(t, "reconcile")))
			if status >= 200 && status < 300 {
				t.Fatal("controller reconcile returned mutation authority")
			}
			memberListenerNoPrivate(t, raw)
		}
	})
	t.Run("fence_capability_is_exact", func(t *testing.T) {
		l, b, f := memberListenerNew(t, "kube_allocator_fence_reader")
		b.variant = "fence_capability"
		if err := l.Start(context.Background()); err != nil {
			t.Fatal(err)
		}
		status, raw := memberListenerResponse(t, nativeProbeListenerClient(t, f, &f.client), memberListenerRequest(t, l.Address(), b, "read", nil))
		if status >= 200 && status < 300 {
			t.Fatal("fence reader obtained another capability context")
		}
		memberListenerNoPrivate(t, raw)
	})
	t.Run("opaque_permit_only_serializes_privately", func(t *testing.T) {
		_, b, _ := memberListenerNew(t, "kube_member_writer")
		permit, err := b.Redeem(context.Background(), memberListenerSelectors())
		if err != nil {
			t.Fatal(err)
		}
		for _, v := range []any{permit, &permit} {
			if raw, err := json.Marshal(v); err == nil || len(raw) > 0 {
				t.Fatal("ordinary opaque permit JSON exposed wire")
			}
			for _, secret := range []string{"settlement_token", base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))} {
				if strings.Contains(fmt.Sprintf("%v %+v %#v", v, v, v), secret) {
					t.Fatal("ordinary opaque permit formatting exposed token")
				}
			}
		}
		safe, err := permit.PublicContext()
		if err != nil {
			t.Fatal(err)
		}
		safe.Node.Name = "changed"
		again, err := permit.PublicContext()
		if err != nil || again.Node.Name != "nw-ci-member" {
			t.Fatal("safe context getter aliased private permit")
		}
		var private bytes.Buffer
		if err := permit.WritePrivateJSON(&private); err != nil || !bytes.Contains(private.Bytes(), []byte("settlement_token")) {
			t.Fatal("explicit private permit representation unavailable")
		}
	})
}
func TestNativeMemberListenerPrivateOriginalBoundaries(t *testing.T) {
	for _, action := range []string{"receive", "receive-read"} {
		t.Run(action, func(t *testing.T) {
			role := "kube_member_writer"
			if action == "receive-read" {
				role = "kube_member_reader"
			}
			l, b, f := memberListenerNew(t, role)
			valid := memberListenerBody(t, action)
			var wire map[string]json.RawMessage
			if json.Unmarshal(valid, &wire) != nil {
				t.Fatal("fixture wire invalid")
			}
			mutations := []func(map[string]json.RawMessage){
				func(m map[string]json.RawMessage) { m["binding_name"] = json.RawMessage(`"foreign"`) },
				func(m map[string]json.RawMessage) {
					m["permit_id"] = json.RawMessage(`"00000000-0000-0000-0000-000000000000"`)
				},
				func(m map[string]json.RawMessage) { m["role"] = json.RawMessage(`"writer"`) },
				func(m map[string]json.RawMessage) {
					raw, _ := json.Marshal(bytes.Repeat([]byte("x"), model.CapacityNativeWorkerMemberMaxOriginalBytes+1))
					m["original_return"] = raw
				},
			}
			if action == "receive" {
				mutations = append(mutations, func(m map[string]json.RawMessage) { m["settlement_token"] = json.RawMessage(`"bad-token"`) })
			} else {
				mutations = append(mutations, func(m map[string]json.RawMessage) { m["read_id"] = json.RawMessage(`""`) }, func(m map[string]json.RawMessage) { m["kind"] = json.RawMessage(`"effect"`) })
			}
			for _, change := range mutations {
				copyWire := map[string]json.RawMessage{}
				for k, v := range wire {
					copyWire[k] = bytes.Clone(v)
				}
				change(copyWire)
				raw, err := json.Marshal(copyWire)
				if err != nil {
					t.Fatal(err)
				}
				body := &nativeProbeListenerRequestBody{raw: raw}
				w := httptest.NewRecorder()
				l.state.handle(w, memberListenerDirect(t, b, f, action, body))
				memberListenerRecordedSource(t, w)
				if w.Code >= 200 && w.Code < 300 || b.count() != 0 || body.closes != 1 {
					t.Fatal("invalid private original crossed bound custody")
				}
				memberListenerNoPrivate(t, w.Body.Bytes())
			}
			body := &nativeProbeListenerRequestBody{raw: bytes.Repeat([]byte("x"), model.CapacityNativeWorkerMemberMaxReceiveBytes+1)}
			w := httptest.NewRecorder()
			l.state.handle(w, memberListenerDirect(t, b, f, action, body))
			if w.Code >= 200 && w.Code < 300 || body.closes != 1 || b.count() != 0 {
				t.Fatal("oversize original request reached backend")
			}
		})
	}
}
func TestNativeMemberListenerOfficialStockWireAndHeldResult(t *testing.T) {
	l, b, f := memberListenerNew(t, "stock_scheduler")
	if err := l.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	client := nativeProbeListenerClient(t, f, &f.client)
	stock := NativeWorkerSchedulerBinding{PodName: "nw-ci-pod", PodNamespace: "ci-native", PodUID: memberListenerTestPermitID, Node: "nw-ci-node"}
	raw, err := json.Marshal(memberListenerUpstreamExtenderBindingArgs{PodName: stock.PodName, PodNamespace: stock.PodNamespace, PodUID: stock.PodUID, Node: stock.Node})
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || len(fields) != 4 {
		t.Fatal("stock args not official four fields")
	}
	for _, field := range []string{"PodName", "PodNamespace", "PodUID", "Node"} {
		if _, ok := fields[field]; !ok {
			t.Fatal("official stock field missing", field)
		}
	}
	status, out := memberListenerResponse(t, client, memberListenerRequest(t, l.Address(), b, "bind", raw))
	if status != 200 || strings.TrimSpace(string(out)) != `{"Error":""}` {
		t.Fatal("stock scheduler without SDK headers was not accepted")
	}
	b.mu.Lock()
	observed := b.binding
	b.fail = true
	b.mu.Unlock()
	if observed != stock {
		t.Fatal("stock binding identity changed before backend")
	}
	status, out = memberListenerResponse(t, client, memberListenerRequest(t, l.Address(), b, "bind", raw))
	if status != 200 || strings.TrimSpace(string(out)) != `{"Error":"native placement held"}` {
		t.Fatal("backend failure was reported as successful Bind or broke official result")
	}
	for _, bad := range []string{
		`{"pod_name":"nw-ci-pod","PodNamespace":"ci-native","PodUID":"` + memberListenerTestPermitID + `","Node":"nw-ci-node"}`,
		`{"podName":"nw-ci-pod","podNamespace":"ci-native","podUID":"` + memberListenerTestPermitID + `","node":"nw-ci-node"}`,
		`{"podName":"nw-ci-pod","PodNamespace":"ci-native","PodUID":"` + memberListenerTestPermitID + `","Node":"nw-ci-node"}`,
		`{"PodName":"nw-ci-pod","podNamespace":"ci-native","PodUID":"` + memberListenerTestPermitID + `","Node":"nw-ci-node"}`,
		`{"PodName":"nw-ci-pod","PodNamespace":"ci-native","podUID":"` + memberListenerTestPermitID + `","Node":"nw-ci-node"}`,
		`{"PodName":"nw-ci-pod","PodNamespace":"ci-native","PodUID":"` + memberListenerTestPermitID + `","node":"nw-ci-node"}`,
		`{"PodName":"nw-ci-pod","podName":"nw-ci-pod","PodNamespace":"ci-native","PodUID":"` + memberListenerTestPermitID + `","Node":"nw-ci-node"}`,
		`{"PodName":"nw-ci-pod","PodNamespace":"ci-native","PodUID":"` + memberListenerTestPermitID + `","Node":"floor-node"}`,
		`{"PodName":"nwp-run20-cp","PodNamespace":"ci-native","PodUID":"` + memberListenerTestPermitID + `","Node":"nw-ci-node"}`,
		`{"PodName":"nw-ci-pod","PodNamespace":"ci-native","PodUID":"` + memberListenerTestPermitID + `","Node":"nw-ci-node","role":"stock_scheduler"}`,
		string(raw) + " {}", strings.Repeat("x", model.CapacityNativeWorkerMemberMaxSelectorBytes+1),
	} {
		before := b.count()
		status, out = memberListenerResponse(t, client, memberListenerRequest(t, l.Address(), b, "bind", []byte(bad)))
		if status >= 200 && status < 300 || b.count() != before {
			t.Fatal("stock alias/free target/name/oversize reached backend")
		}
		memberListenerNoPrivate(t, out)
	}
}

func TestNativeMemberListenerCopiedHandleOwnsLifetimeAfterStartCancellation(t *testing.T) {
	l, b, f := memberListenerNew(t, "kube_member_reader")
	copied := *l
	ctx, cancel := context.WithCancel(context.Background())
	if err := copied.Start(ctx); err != nil {
		t.Fatal(err)
	}
	cancel()
	if copied.Address() == "" || copied.Address() != l.Address() || l.Start(context.Background()) == nil {
		t.Fatal("copied handle duplicated receiving state")
	}
	client := nativeProbeListenerClient(t, f, &f.client)
	status, raw := memberListenerResponse(t, client, memberListenerRequest(t, l.Address(), b, "read", nil))
	if status != 200 {
		t.Fatal("start context cancellation killed independent receiving lifetime")
	}
	memberListenerNoPrivate(t, raw)
	if err := copied.Close(); err != nil {
		t.Fatal(err)
	}
	if l.Close() != nil || copied.Start(context.Background()) == nil || l.Start(context.Background()) == nil {
		t.Fatal("closing one handle did not seal all copies")
	}
	before := b.count()
	body := &nativeProbeListenerRequestBody{}
	w := httptest.NewRecorder()
	l.state.handle(w, memberListenerDirect(t, b, f, "read", body))
	memberListenerRecordedSource(t, w)
	if w.Code != http.StatusServiceUnavailable || body.reads != 0 || b.count() != before {
		t.Fatal("closed handle accepted another callback")
	}
	if _, err := b.Read(context.Background(), memberListenerSelectors()); err != nil {
		t.Fatal("listener stole borrowed backend ownership")
	}
}
func TestNativeMemberListenerCopiedHandleFiniteCloseKeepsStickyUnjoinedFailure(t *testing.T) {
	f := nativeProbeListenerTLS(t)
	f.config.BindingName = "source-owned-member"
	c := NativeWorkerMemberListenerConfig{Role: "kube_member_reader", Transport: f.config}
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	b := &memberListenerBackendFixture{config: c, calls: map[string]int{}, entered: entered, release: release, ignoreCancel: true}
	l, err := newNativeWorkerMemberListener(c, b, nativeProbeListenerTestSource)
	if err != nil {
		t.Fatal(err)
	}
	copied := *l
	t.Cleanup(func() { unblock(); _ = l.Close() })
	if err := l.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	client := nativeProbeListenerClient(t, f, &f.client)
	client.Timeout = 20 * time.Second
	returned := make(chan struct{})
	req := memberListenerRequest(t, l.Address(), b, "read", nil)
	go func() {
		defer close(returned)
		out, err := client.Do(req)
		if err == nil {
			_, _ = io.Copy(io.Discard, out.Body)
			_ = out.Body.Close()
		}
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("real TLS callback did not enter borrowed backend")
	}
	closed := make(chan error, 1)
	go func() { closed <- copied.Close() }()
	select {
	case err := <-closed:
		if err == nil {
			t.Fatal("unjoined callback gained successful Close")
		}
	case <-time.After(12 * time.Second):
		t.Fatal("copied handle Close exceeded finite bound")
	}
	l.state.mu.Lock()
	idle := l.state.idle
	l.state.mu.Unlock()
	select {
	case <-idle:
		t.Fatal("non-cooperative borrowed callback was claimed joined")
	default:
	}
	unblock()
	select {
	case <-idle:
	case <-time.After(2 * time.Second):
		t.Fatal("released borrowed callback did not finish")
	}
	select {
	case <-returned:
	case <-time.After(2 * time.Second):
		t.Fatal("owned HTTP caller did not finish")
	}
	if l.Close() == nil || copied.Close() == nil || l.Start(context.Background()) == nil {
		t.Fatal("copy or later Close erased original unresolved failure")
	}
	b.mu.Lock()
	b.entered = nil
	b.release = nil
	b.mu.Unlock()
	if _, err := b.Read(context.Background(), memberListenerSelectors()); err != nil {
		t.Fatal("listener closed borrowed backend")
	}
}
