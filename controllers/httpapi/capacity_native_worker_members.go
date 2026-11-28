package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"strings"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

const nativeMemberSchedulerBindPath = "/internal/capacity/native-workers/native-scheduler/bind"

var errNativeMemberListener = errors.New("protected Native member callback unavailable")
var nativeMemberDNSLabel = regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$`)
var nativeMemberDNSName = regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9.]{0,251}[a-z0-9])?$`)

// Private, protected composition only. Stock profile facts come from the
// installer; they are never accepted as identity assertions in HTTP input.
type NativeWorkerMemberListenerConfig struct {
	Role                     string
	Transport                NativeWorkerProbeResourceListenerConfig
	StockProfileSourceCommit string
	StockProfileSHA256       string
}

func (NativeWorkerMemberListenerConfig) String() string {
	return "[private Native member listener configuration]"
}
func (c NativeWorkerMemberListenerConfig) GoString() string { return c.String() }
func (NativeWorkerMemberListenerConfig) MarshalJSON() ([]byte, error) {
	return []byte(`{"private_native_member_listener_configuration":"redacted"}`), nil
}

// Exact upstream ExtenderBindingArgs wire. Backend owns current Pod UID,
// controller, fence and useful-capacity validation and the sole Binding send.
type NativeWorkerSchedulerBinding struct {
	PodName      string `json:"PodName"`
	PodNamespace string `json:"PodNamespace"`
	PodUID       string `json:"PodUID"`
	Node         string `json:"Node"`
}

type NativeWorkerMemberCallbacks interface {
	Read(context.Context, model.CapacityNativeWorkerMemberSelectors) (model.CapacityNativeWorkerMemberRead, error)
	ReadAllocatorFence(context.Context, model.CapacityNativeWorkerMemberSelectors) (model.CapacityNativeWorkerAllocatorFenceRead, error)
	Redeem(context.Context, model.CapacityNativeWorkerMemberSelectors) (model.CapacityNativeWorkerMemberPermit, error)
	Receive(context.Context, model.CapacityNativeWorkerMemberReceive) error
	ReceiveRead(context.Context, model.CapacityNativeWorkerMemberReadOriginal) error
	Reconcile(context.Context, model.CapacityNativeWorkerMemberSelectors) (model.CapacityNativeWorkerMemberRead, error)
	Bind(context.Context, NativeWorkerSchedulerBinding) error
}

// Copies share owned receiving state, never a copied mutex or caller TLS key.
type NativeWorkerMemberListener struct{ state *nativeMemberListenerState }
type nativeMemberListenerState struct {
	*nativeWorkerCallbackTransport
	config  NativeWorkerMemberListenerConfig
	backend NativeWorkerMemberCallbacks
}

func (NativeWorkerMemberListener) String() string     { return "[private Native member callback listener]" }
func (l NativeWorkerMemberListener) GoString() string { return l.String() }
func (NativeWorkerMemberListener) MarshalJSON() ([]byte, error) {
	return []byte(`{"private_native_member_listener":"redacted"}`), nil
}

func NewNativeWorkerMemberListener(c NativeWorkerMemberListenerConfig, backend NativeWorkerMemberCallbacks) (*NativeWorkerMemberListener, error) {
	return newNativeWorkerMemberListener(c, backend, capacity.CurrentGuestCoreSource())
}

// Source injection is private to deterministic CI, never an HTTP or env input.
func newNativeWorkerMemberListener(c NativeWorkerMemberListenerConfig, backend NativeWorkerMemberCallbacks, source string) (*NativeWorkerMemberListener, error) {
	if backend == nil || reflect.ValueOf(backend).Kind() == reflect.Pointer && reflect.ValueOf(backend).IsNil() {
		return nil, errNativeMemberListener
	}
	t := c.Transport
	switch c.Role {
	case "stock_scheduler":
		if t.SDKSourceCommit != "" || t.SDKScopeSHA256 != "" || t.BearerTokenSHA256 != "" || !nativeWorkerPhaseSourceCommit.MatchString(c.StockProfileSourceCommit) || !nativeProbeResourceSHA.MatchString(c.StockProfileSHA256) {
			return nil, errNativeMemberListener
		}
	case "kube_member_writer", "kube_member_reader", "kube_allocator_fence_reader", "member_controller":
		if !nativeWorkerPhaseSourceCommit.MatchString(t.SDKSourceCommit) || !nativeProbeResourceSHA.MatchString(t.SDKScopeSHA256) || !nativeProbeResourceSHA.MatchString(t.BearerTokenSHA256) || c.StockProfileSourceCommit != "" || c.StockProfileSHA256 != "" || c.Role == "member_controller" && t.SDKSourceCommit != source {
			return nil, errNativeMemberListener
		}
	default:
		return nil, errNativeMemberListener
	}
	s := &nativeMemberListenerState{backend: backend}
	transport, cloned, err := newNativeWorkerCallbackTransport(t, source, http.HandlerFunc(s.handle))
	if err != nil {
		return nil, errNativeMemberListener
	}
	c.Transport = cloned
	s.nativeWorkerCallbackTransport, s.config = transport, c
	return &NativeWorkerMemberListener{state: s}, nil
}

func (l *NativeWorkerMemberListener) Start(ctx context.Context) error {
	if l == nil || l.state == nil {
		return errNativeMemberListener
	}
	if l.state.nativeWorkerCallbackTransport.Start(ctx) != nil {
		return errNativeMemberListener
	}
	return nil
}
func (l *NativeWorkerMemberListener) Address() string {
	if l == nil || l.state == nil {
		return ""
	}
	return l.state.nativeWorkerCallbackTransport.Address()
}
func (l *NativeWorkerMemberListener) Close() error {
	if l == nil || l.state == nil {
		return nil
	}
	if l.state.nativeWorkerCallbackTransport.Close() != nil {
		return errNativeMemberListener
	}
	return nil
}

func nativeMemberCanonicalUUID(raw string) bool {
	id, err := uuid.Parse(raw)
	return err == nil && id != uuid.Nil && id.String() == raw
}
func nativeMemberSelectorsValid(in model.CapacityNativeWorkerMemberSelectors, binding string) bool {
	return in.BindingName == binding && nativeMemberCanonicalUUID(in.PermitID)
}
func (s *nativeMemberListenerState) refuse(w http.ResponseWriter, status int) {
	w.WriteHeader(status)
	_, _ = io.WriteString(w, `{"error":"native member callback unavailable"}`)
}
func (s *nativeMemberListenerState) authenticated(r *http.Request) bool {
	if !nativeWorkerCallbackTLSAuthenticated(s.config.Transport, r) {
		return false
	}
	if s.config.Role == "stock_scheduler" {
		return len(r.Header.Values("Authorization")) == 0 && len(r.Header.Values(nativeWorkerPhaseAdapterSourceHeader)) == 0 && len(r.Header.Values(nativeProbeResourceScopeHeader)) == 0
	}
	// The existing framing is independent of TLS ownership and not a probe
	// callback backend. Controller has its own Source/scope/bearer tuple.
	return nativeWorkerCallbackSDKAuthenticated(s.config.Transport, r)
}
func (s *nativeMemberListenerState) endpointBound(e model.CapacityNativeWorkerMemberEndpoint) bool {
	t := s.config.Transport
	return e.BindingName == t.BindingName && e.SourceCommit == t.SDKSourceCommit && e.ScopeSHA256 == t.SDKScopeSHA256
}
func (s *nativeMemberListenerState) contextBound(c model.CapacityNativeWorkerMemberContext, in model.CapacityNativeWorkerMemberSelectors) bool {
	if c.Schema != model.CapacityNativeWorkerMemberContextSchema || c.CoreSourceCommit != s.config.Transport.CoreSourceCommit || c.PermitID != in.PermitID {
		return false
	}
	raw, err := json.Marshal(c)
	if err != nil || len(raw) > model.CapacityNativeWorkerMemberMaxContextBytes {
		return false
	}
	switch s.config.Role {
	case "kube_member_writer":
		return s.endpointBound(c.Actor)
	case "kube_member_reader":
		return s.endpointBound(c.Observer)
	case "member_controller":
		return true // Caller authority is backend-bound, not an SDK tuple.
	}
	return false
}
func (s *nativeMemberListenerState) readBound(out model.CapacityNativeWorkerMemberRead, in model.CapacityNativeWorkerMemberSelectors) bool {
	if out.Schema != model.CapacityNativeWorkerMemberReadSchema || out.BindingName != in.BindingName || out.MutationPermitted || !s.contextBound(out.Context, in) {
		return false
	}
	if s.config.Role == "kube_member_reader" {
		return nativeMemberCanonicalUUID(out.ReadID) && !out.Redeemable
	}
	if s.config.Role == "member_controller" {
		return !out.Redeemable
	}
	return out.ReadID == "" || nativeMemberCanonicalUUID(out.ReadID)
}
func nativeMemberReadBody(r *http.Request, limit int64) ([]byte, error) {
	var raw []byte
	var err, closeErr error
	if r.Body != nil {
		raw, err = io.ReadAll(io.LimitReader(r.Body, limit+1))
		closeErr = r.Body.Close()
	}
	if err != nil || closeErr != nil || r.Context().Err() != nil || int64(len(raw)) > limit {
		clear(raw)
		return nil, errNativeMemberListener
	}
	return raw, nil
}

func (s *nativeMemberListenerState) handle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Yggdrasil-Source-Commit", s.config.Transport.CoreSourceCommit)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	if !s.enter() {
		s.refuse(w, http.StatusServiceUnavailable)
		return
	}
	defer s.leave()
	if !s.authenticated(r) {
		s.refuse(w, http.StatusForbidden)
		return
	}
	if r.URL == nil || r.URL.RawPath != "" || r.URL.ForceQuery || r.URL.Opaque != "" {
		s.refuse(w, http.StatusNotFound)
		return
	}
	if s.config.Role == "stock_scheduler" {
		s.handleStockBind(w, r)
		return
	}
	if !strings.HasPrefix(r.URL.Path, model.CapacityNativeWorkerMemberCallbackBase) {
		s.refuse(w, http.StatusNotFound)
		return
	}
	action := strings.TrimPrefix(r.URL.Path, model.CapacityNativeWorkerMemberCallbackBase)
	get := action == "read" && r.Method == http.MethodGet
	post := r.Method == http.MethodPost && (action == "redeem" || action == "receive" || action == "receive-read" || action == "reconcile")
	allowed := false
	switch s.config.Role {
	case "kube_member_writer":
		allowed = get || post && (action == "redeem" || action == "receive")
	case "kube_member_reader":
		allowed = get || post && action == "receive-read"
	case "kube_allocator_fence_reader":
		allowed = get
	case "member_controller":
		allowed = post && action == "reconcile"
	}
	if !allowed || post && r.URL.RawQuery != "" {
		s.refuse(w, http.StatusNotFound)
		return
	}
	limit := int64(model.CapacityNativeWorkerMemberMaxReceiveBytes)
	if get {
		limit = 0
	} else if action == "redeem" || action == "reconcile" {
		limit = model.CapacityNativeWorkerMemberMaxSelectorBytes
	}
	raw, err := nativeMemberReadBody(r, limit)
	if err != nil {
		s.refuse(w, http.StatusBadRequest)
		return
	}
	defer clear(raw)
	var in model.CapacityNativeWorkerMemberSelectors
	var received model.CapacityNativeWorkerMemberReceive
	var readOriginal model.CapacityNativeWorkerMemberReadOriginal
	switch {
	case get:
		query, err := url.ParseQuery(r.URL.RawQuery)
		if err != nil || len(query) != 2 || len(query["binding_name"]) != 1 || len(query["permit_id"]) != 1 || query.Encode() != r.URL.RawQuery {
			s.refuse(w, http.StatusBadRequest)
			return
		}
		in = model.CapacityNativeWorkerMemberSelectors{BindingName: query.Get("binding_name"), PermitID: query.Get("permit_id")}
	case action == "receive":
		if capacity.DecodeNativeCapacity(json.RawMessage(raw), &received) != nil || received.Schema != model.CapacityNativeWorkerMemberReceiveSchema || len(received.OriginalReturn) > model.CapacityNativeWorkerMemberMaxOriginalBytes || !nativeProbeResourceToken(received.SettlementToken) {
			s.refuse(w, http.StatusBadRequest)
			return
		}
		defer clear(received.OriginalReturn)
		in = model.CapacityNativeWorkerMemberSelectors{BindingName: received.BindingName, PermitID: received.PermitID}
	case action == "receive-read":
		if capacity.DecodeNativeCapacity(json.RawMessage(raw), &readOriginal) != nil || readOriginal.Schema != model.CapacityNativeWorkerMemberReadOriginalSchema || readOriginal.Kind != "kubelet_configz" || !nativeMemberCanonicalUUID(readOriginal.ReadID) || len(readOriginal.OriginalReturn) > model.CapacityNativeWorkerMemberMaxOriginalBytes {
			s.refuse(w, http.StatusBadRequest)
			return
		}
		defer clear(readOriginal.OriginalReturn)
		in = model.CapacityNativeWorkerMemberSelectors{BindingName: readOriginal.BindingName, PermitID: readOriginal.PermitID}
	default:
		if capacity.DecodeNativeCapacity(json.RawMessage(raw), &in) != nil {
			s.refuse(w, http.StatusBadRequest)
			return
		}
	}
	if !nativeMemberSelectorsValid(in, s.config.Transport.BindingName) || r.Context().Err() != nil {
		s.refuse(w, http.StatusBadRequest)
		return
	}
	var output []byte
	switch action {
	case "read", "reconcile":
		if s.config.Role == "kube_allocator_fence_reader" {
			out, e := s.backend.ReadAllocatorFence(r.Context(), in)
			if e != nil || out.Schema != model.CapacityNativeWorkerAllocatorFenceReadSchema || out.BindingName != in.BindingName || out.Context.Schema != model.CapacityNativeWorkerAllocatorFenceContextSchema || out.Context.CreatorPermitID != in.PermitID || out.Context.CoreSourceCommit != s.config.Transport.CoreSourceCommit || out.Context.Observer.Capability != "observe_native_worker_allocator_fence" || !s.endpointBound(out.Context.Observer) {
				s.refuse(w, http.StatusServiceUnavailable)
				return
			}
			output, err = json.Marshal(out)
		} else {
			var out model.CapacityNativeWorkerMemberRead
			if action == "reconcile" {
				out, err = s.backend.Reconcile(r.Context(), in)
			} else {
				out, err = s.backend.Read(r.Context(), in)
			}
			if err != nil || !s.readBound(out, in) {
				s.refuse(w, http.StatusServiceUnavailable)
				return
			}
			output, err = json.Marshal(out)
		}
	case "redeem":
		out, e := s.backend.Redeem(r.Context(), in)
		c, bindingErr := out.PublicContext()
		if e != nil || bindingErr != nil || !s.contextBound(c, in) {
			s.refuse(w, http.StatusServiceUnavailable)
			return
		}
		var buf bytes.Buffer
		err = out.WritePrivateJSON(&buf)
		output = buf.Bytes()
	case "receive":
		if s.backend.Receive(r.Context(), received) != nil {
			s.refuse(w, http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	case "receive-read":
		if s.backend.ReceiveRead(r.Context(), readOriginal) != nil {
			s.refuse(w, http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	defer clear(output)
	if err != nil || len(output) > model.CapacityNativeWorkerMemberMaxReceiveBytes || r.Context().Err() != nil {
		s.refuse(w, http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(output)
}

func nativeMemberWorkloadName(name string) bool {
	if !strings.HasPrefix(name, "nw-") || len(name) > 253 || !nativeMemberDNSName.MatchString(name) {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if !nativeMemberDNSLabel.MatchString(label) {
			return false
		}
	}
	return true
}
func (s *nativeMemberListenerState) handleStockBind(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != nativeMemberSchedulerBindPath || r.Method != http.MethodPost || r.URL.RawQuery != "" {
		s.refuse(w, http.StatusNotFound)
		return
	}
	raw, err := nativeMemberReadBody(r, model.CapacityNativeWorkerMemberMaxSelectorBytes)
	if err != nil {
		s.refuse(w, http.StatusBadRequest)
		return
	}
	defer clear(raw)
	var in NativeWorkerSchedulerBinding
	if capacity.DecodeNativeCapacity(json.RawMessage(raw), &in) != nil || !nativeMemberWorkloadName(in.PodName) || !nativeMemberWorkloadName(in.Node) || !nativeMemberDNSLabel.MatchString(in.PodNamespace) || !nativeMemberCanonicalUUID(in.PodUID) || r.Context().Err() != nil {
		s.refuse(w, http.StatusBadRequest)
		return
	}
	// The official extender protocol carries a result even on HOLD/unknown.
	// A successful HTTP frame never turns a failed backend into a Bind receipt.
	result := struct {
		Error string `json:"Error"`
	}{}
	if s.backend.Bind(r.Context(), in) != nil || r.Context().Err() != nil {
		result.Error = "native placement held"
	}
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(result)
}
