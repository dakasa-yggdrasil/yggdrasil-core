package httpapi

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
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
	mu                   sync.Mutex
	config               NativeWorkerProbeResourceListenerConfig
	backend              NativeWorkerProbeResourceCallbacks
	server               *http.Server
	cancel               context.CancelFunc
	started, closing     bool
	active               int
	idle, served, closed chan struct{}
	closeOnce            sync.Once
	serveErr, closeErr   error
	address              string
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
	if backend == nil || reflect.ValueOf(backend).Kind() == reflect.Pointer && reflect.ValueOf(backend).IsNil() || !nativeWorkerPhaseSourceCommit.MatchString(source) || c.CoreSourceCommit != source || !nativeWorkerPhaseSourceCommit.MatchString(c.SDKSourceCommit) || !nativeProbeResourceID.MatchString(c.BindingName) || c.ServerName == "" || strings.ContainsAny(c.ServerName, "\r\n\x00") || !nativeProbeResourceURI(c.ServerURI) || !nativeProbeResourceURI(c.ClientURI) || !nativeProbeResourceSHA.MatchString(c.ServerLeafSHA256) || !nativeProbeResourceSHA.MatchString(c.ClientLeafSHA256) || !nativeProbeResourceSHA.MatchString(c.BearerTokenSHA256) || !nativeProbeResourceSHA.MatchString(c.SDKScopeSHA256) || c.ClientCAs == nil || c.ClientCAs.Equal(x509.NewCertPool()) {
		return nil, errNativeProbeResourceListener
	}
	host, port, err := net.SplitHostPort(c.ListenAddr)
	n, numberErr := strconv.Atoi(port)
	if err != nil || numberErr != nil || n < 0 || n > 65535 || strconv.Itoa(n) != port || net.JoinHostPort(host, port) != c.ListenAddr {
		return nil, errNativeProbeResourceListener
	}
	if host != "" {
		ip, e := netip.ParseAddr(host)
		if e != nil || ip.String() != host {
			return nil, errNativeProbeResourceListener
		}
	}
	if len(c.ServerCertificate.Certificate) == 0 || len(c.ServerCertificate.Certificate) > 8 {
		return nil, errNativeProbeResourceListener
	}
	pair := tls.Certificate{}
	for _, der := range c.ServerCertificate.Certificate {
		if len(der) == 0 || len(der) > 64<<10 {
			return nil, errNativeProbeResourceListener
		}
		pair.Certificate = append(pair.Certificate, bytes.Clone(der))
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil || !nativeProbeResourceLeaf(leaf, c.ServerURI, c.ServerLeafSHA256, x509.ExtKeyUsageServerAuth, time.Now()) || leaf.VerifyHostname(c.ServerName) != nil {
		return nil, errNativeProbeResourceListener
	}
	encoded, err := x509.MarshalPKCS8PrivateKey(c.ServerCertificate.PrivateKey)
	if err != nil {
		return nil, errNativeProbeResourceListener
	}
	defer clear(encoded)
	pair.PrivateKey, err = x509.ParsePKCS8PrivateKey(encoded)
	signer, ok := pair.PrivateKey.(crypto.Signer)
	if err != nil || !ok {
		return nil, errNativeProbeResourceListener
	}
	public, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil || !bytes.Equal(public, leaf.RawSubjectPublicKeyInfo) {
		return nil, errNativeProbeResourceListener
	}
	pair.Leaf = leaf
	c.ServerCertificate, c.ClientCAs = pair, c.ClientCAs.Clone()
	owned, cancel := context.WithCancel(context.Background())
	idle := make(chan struct{})
	close(idle)
	s := &nativeProbeResourceListenerState{config: c, backend: backend, cancel: cancel, idle: idle, served: make(chan struct{}), closed: make(chan struct{})}
	s.server = &http.Server{Handler: http.HandlerFunc(s.handle), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 20 * time.Second, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 32 << 10, ErrorLog: log.New(io.Discard, "", 0), BaseContext: func(net.Listener) context.Context { return owned }, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}, ClientCAs: c.ClientCAs, ClientAuth: tls.RequireAndVerifyClientCert, NextProtos: []string{"http/1.1"}, SessionTicketsDisabled: true}}
	s.server.SetKeepAlivesEnabled(false)
	return &NativeWorkerProbeResourceListener{state: s}, nil
}

// The startup context controls binding only. Receiving remains alive until Close
// so producer cancellation cannot destroy an original in-flight callback.
func (l *NativeWorkerProbeResourceListener) Start(ctx context.Context) error {
	if l == nil || l.state == nil || ctx == nil || ctx.Err() != nil {
		return errNativeProbeResourceListener
	}
	s := l.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started || s.closing {
		return errNativeProbeResourceListener
	}
	s.started = true
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", s.config.ListenAddr)
	if err != nil || ctx.Err() != nil {
		if listener != nil {
			_ = listener.Close()
		}
		s.serveErr = errNativeProbeResourceListener
		close(s.served)
		return errNativeProbeResourceListener
	}
	s.address = listener.Addr().String()
	go func() {
		defer close(s.served)
		err := s.server.Serve(tls.NewListener(listener, s.server.TLSConfig))
		s.mu.Lock()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.serveErr = errNativeProbeResourceListener
		}
		s.mu.Unlock()
	}()
	return nil
}

func (l *NativeWorkerProbeResourceListener) Address() string {
	if l == nil || l.state == nil {
		return ""
	}
	l.state.mu.Lock()
	defer l.state.mu.Unlock()
	return l.state.address
}

// Close owns only this listener. Backend, database and caller TLS handles remain
// borrowed. A forced/unfinished shutdown returns an error, never a joined claim.
func (l *NativeWorkerProbeResourceListener) Close() error {
	if l == nil || l.state == nil {
		return nil
	}
	s := l.state
	s.closeOnce.Do(func() {
		defer close(s.closed)
		s.mu.Lock()
		s.closing = true
		started, idle := s.started, s.idle
		s.mu.Unlock()
		ctx, cancel := context.WithTimeout(context.Background(), nativeProbeResourceCloseWait)
		defer cancel()
		if err := s.server.Shutdown(ctx); err != nil {
			s.closeErr = errNativeProbeResourceListener
			s.cancel()
			_ = s.server.Close()
		}
		s.cancel()
		join, cancelJoin := context.WithTimeout(context.Background(), nativeProbeResourceCloseWait)
		defer cancelJoin()
		if started {
			select {
			case <-s.served:
			case <-join.Done():
				s.closeErr = errNativeProbeResourceListener
			}
		}
		select {
		case <-idle:
		case <-join.Done():
			s.closeErr = errNativeProbeResourceListener
		}
		s.mu.Lock()
		if s.serveErr != nil {
			s.closeErr = errNativeProbeResourceListener
		}
		s.mu.Unlock()
	})
	<-s.closed
	return s.closeErr
}

func (s *nativeProbeResourceListenerState) enter() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing {
		return false
	}
	if s.active == 0 {
		s.idle = make(chan struct{})
	}
	s.active++
	return true
}
func (s *nativeProbeResourceListenerState) leave() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.active--
	if s.active == 0 {
		close(s.idle)
	}
}
func (s *nativeProbeResourceListenerState) refuse(w http.ResponseWriter, status int) {
	w.WriteHeader(status)
	_, _ = io.WriteString(w, `{"error":"native probe callback unavailable"}`)
}
func (s *nativeProbeResourceListenerState) authenticated(r *http.Request) bool {
	c := s.config
	if r.TLS == nil || r.TLS.Version < tls.VersionTLS13 || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 || !nativeProbeResourceLeaf(r.TLS.PeerCertificates[0], c.ClientURI, c.ClientLeafSHA256, x509.ExtKeyUsageClientAuth, time.Now()) {
		return false
	}
	bearer, source, scope := r.Header.Values("Authorization"), r.Header.Values(nativeWorkerPhaseAdapterSourceHeader), r.Header.Values(nativeProbeResourceScopeHeader)
	if len(bearer) != 1 || len(source) != 1 || len(scope) != 1 || source[0] != c.SDKSourceCommit || scope[0] != c.SDKScopeSHA256 || !strings.HasPrefix(bearer[0], "Bearer ") {
		return false
	}
	token := strings.TrimPrefix(bearer[0], "Bearer ")
	if len(token) < 32 || len(token) > 8192 {
		return false
	}
	for _, ch := range token {
		if ch < 33 || ch > 126 {
			return false
		}
	}
	return subtle.ConstantTimeCompare([]byte(nativeProbeResourceDigest([]byte(token))), []byte(c.BearerTokenSHA256)) == 1
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
