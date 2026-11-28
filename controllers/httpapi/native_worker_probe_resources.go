package httpapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

const nativeProbeResourceBase = "/internal/capacity/native-workers/probe-resources/"
const nativeProbeResourceScopeHeader = "X-Yggdrasil-Adapter-Scope-SHA256"
const nativeProbeResourceCloseWait = 5 * time.Second

var errNativeProbeResourceListener = errors.New("protected native probe callback unavailable")
var nativeProbeResourceID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$`)
var nativeProbeResourceSHA = regexp.MustCompile(`^[a-f0-9]{64}$`)

// These callbacks are installed only by protected process composition. They own
// journal authority and raw custody; this listener never manufactures a proof.
type NativeWorkerProbeResourceCallbacks interface {
	Read(context.Context, model.NativeWorkerProbeResourceInput) (model.NativeWorkerProbeResourceContext, error)
	Bootstrap(context.Context, model.NativeWorkerProbeResourceInput) (model.NativeWorkerProbeResourceBootstrap, error)
	Redeem(context.Context, model.NativeWorkerProbeResourceInput) (model.NativeWorkerProbeResourcePermit, error)
	Receive(context.Context, model.NativeWorkerProbeResourceReceive) error
}

// Private Go configuration, never a workflow input or public manifest. The
// loader owns protected files; the listener independently clones TLS material.
type NativeWorkerProbeResourceListenerConfig struct {
	ListenAddr, ServerName, CoreSourceCommit, BindingName        string
	SDKSourceCommit, SDKScopeSHA256, ServerLeafSHA256, ServerURI string
	ClientLeafSHA256, ClientURI, BearerTokenSHA256               string
	ServerCertificate                                            tls.Certificate
	ClientCAs                                                    *x509.CertPool
}

func (NativeWorkerProbeResourceListenerConfig) String() string {
	return "[private native probe listener configuration]"
}
func (c NativeWorkerProbeResourceListenerConfig) GoString() string { return c.String() }
func (NativeWorkerProbeResourceListenerConfig) MarshalJSON() ([]byte, error) {
	return []byte(`{"private_native_probe_listener_configuration":"redacted"}`), nil
}

// Copying the handle never copies its mutex or exposes the owned private key.
type NativeWorkerProbeResourceListener struct {
	state *nativeProbeResourceListenerState
}

func (NativeWorkerProbeResourceListener) String() string {
	return "[private native probe callback listener]"
}
func (s NativeWorkerProbeResourceListener) GoString() string { return s.String() }
func (NativeWorkerProbeResourceListener) MarshalJSON() ([]byte, error) {
	return []byte(`{"private_native_probe_listener":"redacted"}`), nil
}

type nativeProbeResourceListenerState struct {
	*nativeWorkerCallbackTransport
	config  NativeWorkerProbeResourceListenerConfig
	backend NativeWorkerProbeResourceCallbacks
}

func nativeProbeResourceDigest(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func nativeProbeResourceURI(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "spiffe" && u.Host != "" && u.Path != "" && u.Opaque == "" && u.RawPath == "" && u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" && u.User == nil && u.String() == raw
}
func nativeProbeResourceLeaf(cert *x509.Certificate, uri, digest string, usage x509.ExtKeyUsage, now time.Time) bool {
	if cert == nil || cert.IsCA || now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) || len(cert.URIs) != 1 || cert.URIs[0] == nil || cert.URIs[0].String() != uri || nativeProbeResourceDigest(cert.Raw) != digest {
		return false
	}
	for _, actual := range cert.ExtKeyUsage {
		if actual == usage {
			return true
		}
	}
	return false
}

func NewNativeWorkerProbeResourceListener(c NativeWorkerProbeResourceListenerConfig, backend NativeWorkerProbeResourceCallbacks) (*NativeWorkerProbeResourceListener, error) {
	return newNativeWorkerProbeResourceListener(c, backend, capacity.CurrentGuestCoreSource())
}

// Source injection is package-private for deterministic CI, never HTTP/env input.
func newNativeWorkerProbeResourceListener(c NativeWorkerProbeResourceListenerConfig, backend NativeWorkerProbeResourceCallbacks, source string) (*NativeWorkerProbeResourceListener, error) {
	if backend == nil || reflect.ValueOf(backend).Kind() == reflect.Pointer && reflect.ValueOf(backend).IsNil() || !nativeWorkerPhaseSourceCommit.MatchString(c.SDKSourceCommit) || !nativeProbeResourceSHA.MatchString(c.BearerTokenSHA256) || !nativeProbeResourceSHA.MatchString(c.SDKScopeSHA256) {
		return nil, errNativeProbeResourceListener
	}
	s := &nativeProbeResourceListenerState{backend: backend}
	transport, cloned, err := newNativeWorkerCallbackTransport(c, source, http.HandlerFunc(s.handle))
	if err != nil {
		return nil, err
	}
	s.nativeWorkerCallbackTransport, s.config = transport, cloned
	return &NativeWorkerProbeResourceListener{state: s}, nil
}

// The startup context controls binding only; explicit Close joins receiving.
func (l *NativeWorkerProbeResourceListener) Start(ctx context.Context) error {
	if l == nil || l.state == nil {
		return errNativeProbeResourceListener
	}
	return l.state.nativeWorkerCallbackTransport.Start(ctx)
}
func (l *NativeWorkerProbeResourceListener) Address() string {
	if l == nil || l.state == nil {
		return ""
	}
	return l.state.nativeWorkerCallbackTransport.Address()
}
func (l *NativeWorkerProbeResourceListener) Close() error {
	if l == nil || l.state == nil {
		return nil
	}
	return l.state.nativeWorkerCallbackTransport.Close()
}

func (s *nativeProbeResourceListenerState) refuse(w http.ResponseWriter, status int) {
	w.WriteHeader(status)
	_, _ = io.WriteString(w, `{"error":"native probe callback unavailable"}`)
}
func (s *nativeProbeResourceListenerState) authenticated(r *http.Request) bool {
	c := s.config
	if !nativeWorkerCallbackTLSAuthenticated(c, r) {
		return false
	}
	return nativeWorkerCallbackSDKAuthenticated(c, r)
}

func nativeProbeResourceInputValid(in model.NativeWorkerProbeResourceInput, binding string) bool {
	id, err := uuid.Parse(in.RunID)
	if in.BindingName != binding || err != nil || id == uuid.Nil || id.String() != in.RunID {
		return false
	}
	switch in.Slot {
	case "floor_pod", "candidate_pod", "floor_service", "candidate_service", "admission_secret", "floor_secret", "candidate_secret", "network_policy", "startup_challenge":
		return true
	}
	return false
}
func nativeProbeResourceToken(token string) bool {
	b, err := base64.RawURLEncoding.DecodeString(token)
	return err == nil && len(b) == 32 && len(token) == 43 && base64.RawURLEncoding.EncodeToString(b) == token
}
func (s *nativeProbeResourceListenerState) bound(c model.NativeWorkerProbeResourceContext, in model.NativeWorkerProbeResourceInput) bool {
	return c.Schema == model.NativeWorkerProbeResourceContextSchema && c.BindingName == in.BindingName && c.RunID == in.RunID && c.Slot == in.Slot && c.CoreSourceCommit == s.config.CoreSourceCommit && c.SDKSourceCommit == s.config.SDKSourceCommit && c.SDKScopeSHA256 == s.config.SDKScopeSHA256
}

// The startup slot is the one reviewed three-step Pod CAS. It is never a
// generic array/object writer; detailed paths/UID/RV stay backend/SDK-owned.
func nativeProbeResourceBootstrapShape(out model.NativeWorkerProbeResourceBootstrap) bool {
	if len(out.ObjectJSON) == 0 || len(out.ObjectJSON) > 256<<10 || !json.Valid(out.ObjectJSON) {
		return false
	}
	raw := bytes.TrimSpace(out.ObjectJSON)
	switch out.Context.Op {
	case "create":
		return out.Context.Slot != "startup_challenge" && raw[0] == '{'
	case "startup_patch":
		if out.Context.Slot != "startup_challenge" || raw[0] != '[' {
			return false
		}
		var patch []json.RawMessage
		return json.Unmarshal(raw, &patch) == nil && len(patch) == 3
	default:
		return false
	}
}

func (s *nativeProbeResourceListenerState) handle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Yggdrasil-Source-Commit", s.config.CoreSourceCommit)
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
	if r.URL == nil || r.URL.RawPath != "" || r.URL.ForceQuery || r.URL.Opaque != "" || !strings.HasPrefix(r.URL.Path, nativeProbeResourceBase) {
		s.refuse(w, http.StatusNotFound)
		return
	}
	action := strings.TrimPrefix(r.URL.Path, nativeProbeResourceBase)
	get := (action == "read" || action == "bootstrap") && r.Method == http.MethodGet
	post := (action == "redeem" || action == "receive") && r.Method == http.MethodPost
	if !get && !post || post && r.URL.RawQuery != "" {
		s.refuse(w, http.StatusNotFound)
		return
	}
	limit := int64(2 << 20)
	if get {
		limit = 0
	}
	var raw []byte
	var err, errorClose error
	if r.Body != nil {
		raw, err = io.ReadAll(io.LimitReader(r.Body, limit+1))
		errorClose = r.Body.Close()
	}
	defer clear(raw)
	if err != nil || errorClose != nil || r.Context().Err() != nil || int64(len(raw)) > limit {
		s.refuse(w, http.StatusBadRequest)
		return
	}
	var in model.NativeWorkerProbeResourceInput
	var received model.NativeWorkerProbeResourceReceive
	if get {
		query, e := url.ParseQuery(r.URL.RawQuery)
		if e != nil || len(query) != 3 || len(query["binding_name"]) != 1 || len(query["run_id"]) != 1 || len(query["slot"]) != 1 || query.Encode() != r.URL.RawQuery {
			s.refuse(w, http.StatusBadRequest)
			return
		}
		in = model.NativeWorkerProbeResourceInput{BindingName: query.Get("binding_name"), RunID: query.Get("run_id"), Slot: query.Get("slot")}
	} else if action == "receive" {
		if capacity.DecodeNativeCapacity(json.RawMessage(raw), &received) != nil || len(received.OriginalReturn) > 1<<20 || !nativeProbeResourceToken(received.SettlementToken) {
			s.refuse(w, http.StatusBadRequest)
			return
		}
		in = model.NativeWorkerProbeResourceInput{BindingName: received.BindingName, RunID: received.RunID, Slot: received.Slot}
	} else if capacity.DecodeNativeCapacity(json.RawMessage(raw), &in) != nil {
		s.refuse(w, http.StatusBadRequest)
		return
	}
	if !nativeProbeResourceInputValid(in, s.config.BindingName) || r.Context().Err() != nil {
		s.refuse(w, http.StatusBadRequest)
		return
	}
	var output []byte
	switch action {
	case "read":
		out, e := s.backend.Read(r.Context(), in)
		if e != nil || !s.bound(out, in) {
			s.refuse(w, http.StatusServiceUnavailable)
			return
		}
		output, err = json.Marshal(out)
	case "bootstrap":
		out, e := s.backend.Bootstrap(r.Context(), in)
		if e != nil || out.Schema != model.NativeWorkerProbeResourceBootstrapSchema || !s.bound(out.Context, in) || !nativeProbeResourceBootstrapShape(out) {
			s.refuse(w, http.StatusServiceUnavailable)
			return
		}
		output, err = out.MarshalPrivateJSON()
	case "redeem":
		out, e := s.backend.Redeem(r.Context(), in)
		if e != nil || out.Schema != model.NativeWorkerProbeResourcePermitSchema || !s.bound(out.Context, in) || !nativeProbeResourceToken(out.SettlementToken) {
			s.refuse(w, http.StatusServiceUnavailable)
			return
		}
		output, err = out.MarshalPrivateJSON()
	case "receive":
		if s.backend.Receive(r.Context(), received) != nil {
			s.refuse(w, http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	defer clear(output)
	if err != nil || len(output) > 2<<20 || r.Context().Err() != nil {
		s.refuse(w, http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(output)
}
