package httpapi

import (
	"bytes"
	"context"
	"crypto"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/goroutine"
)

// Transport owns cloned TLS material and its finite receiving lifetime only.
// Caller-specific SDK headers and callback authority remain in each listener.
type nativeWorkerCallbackTransport struct {
	mu                   sync.Mutex
	listenAddr           string
	server               *http.Server
	cancel               context.CancelFunc
	started, closing     bool
	active               int
	idle, served, closed chan struct{}
	closeOnce            sync.Once
	serveErr, closeErr   error
	address              string
}

func newNativeWorkerCallbackTransport(c NativeWorkerProbeResourceListenerConfig, source string, handler http.Handler) (*nativeWorkerCallbackTransport, NativeWorkerProbeResourceListenerConfig, error) {
	if !nativeWorkerPhaseSourceCommit.MatchString(source) || c.CoreSourceCommit != source || !nativeProbeResourceID.MatchString(c.BindingName) || c.ServerName == "" || strings.ContainsAny(c.ServerName, "\r\n\x00") || !nativeProbeResourceURI(c.ServerURI) || !nativeProbeResourceURI(c.ClientURI) || !nativeProbeResourceSHA.MatchString(c.ServerLeafSHA256) || !nativeProbeResourceSHA.MatchString(c.ClientLeafSHA256) || c.ClientCAs == nil || c.ClientCAs.Equal(x509.NewCertPool()) || handler == nil {
		return nil, c, errNativeProbeResourceListener
	}
	host, port, err := net.SplitHostPort(c.ListenAddr)
	n, numberErr := strconv.Atoi(port)
	if err != nil || numberErr != nil || n < 0 || n > 65535 || strconv.Itoa(n) != port || net.JoinHostPort(host, port) != c.ListenAddr {
		return nil, c, errNativeProbeResourceListener
	}
	if host != "" {
		ip, e := netip.ParseAddr(host)
		if e != nil || ip.String() != host {
			return nil, c, errNativeProbeResourceListener
		}
	}
	if len(c.ServerCertificate.Certificate) == 0 || len(c.ServerCertificate.Certificate) > 8 {
		return nil, c, errNativeProbeResourceListener
	}
	pair := tls.Certificate{}
	for _, der := range c.ServerCertificate.Certificate {
		if len(der) == 0 || len(der) > 64<<10 {
			return nil, c, errNativeProbeResourceListener
		}
		pair.Certificate = append(pair.Certificate, bytes.Clone(der))
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil || !nativeProbeResourceLeaf(leaf, c.ServerURI, c.ServerLeafSHA256, x509.ExtKeyUsageServerAuth, time.Now()) || leaf.VerifyHostname(c.ServerName) != nil {
		return nil, c, errNativeProbeResourceListener
	}
	encoded, err := x509.MarshalPKCS8PrivateKey(c.ServerCertificate.PrivateKey)
	if err != nil {
		return nil, c, errNativeProbeResourceListener
	}
	defer clear(encoded)
	pair.PrivateKey, err = x509.ParsePKCS8PrivateKey(encoded)
	signer, ok := pair.PrivateKey.(crypto.Signer)
	if err != nil || !ok {
		return nil, c, errNativeProbeResourceListener
	}
	public, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil || !bytes.Equal(public, leaf.RawSubjectPublicKeyInfo) {
		return nil, c, errNativeProbeResourceListener
	}
	pair.Leaf = leaf
	c.ServerCertificate, c.ClientCAs = pair, c.ClientCAs.Clone()
	owned, cancel := context.WithCancel(context.Background())
	idle := make(chan struct{})
	close(idle)
	s := &nativeWorkerCallbackTransport{listenAddr: c.ListenAddr, cancel: cancel, idle: idle, served: make(chan struct{}), closed: make(chan struct{})}
	s.server = &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 20 * time.Second, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 32 << 10, ErrorLog: log.New(io.Discard, "", 0), BaseContext: func(net.Listener) context.Context { return owned }, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}, ClientCAs: c.ClientCAs, ClientAuth: tls.RequireAndVerifyClientCert, NextProtos: []string{"http/1.1"}, SessionTicketsDisabled: true}}
	s.server.SetKeepAlivesEnabled(false)
	return s, c, nil
}

// The startup context controls binding only. Receiving remains alive until Close
// so producer cancellation cannot destroy an original in-flight callback.
func (s *nativeWorkerCallbackTransport) Start(ctx context.Context) error {
	if s == nil || ctx == nil || ctx.Err() != nil {
		return errNativeProbeResourceListener
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started || s.closing {
		return errNativeProbeResourceListener
	}
	s.started = true
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", s.listenAddr)
	if err != nil || ctx.Err() != nil {
		if listener != nil {
			_ = listener.Close()
		}
		s.serveErr = errNativeProbeResourceListener
		close(s.served)
		return errNativeProbeResourceListener
	}
	s.address = listener.Addr().String()
	goroutine.SafeGo("native_worker_callback_serve", func() {
		returned := false
		defer func() {
			if !returned {
				s.mu.Lock()
				s.serveErr = errNativeProbeResourceListener
				s.mu.Unlock()
			}
			close(s.served)
		}()
		err := s.server.Serve(tls.NewListener(listener, s.server.TLSConfig))
		s.mu.Lock()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.serveErr = errNativeProbeResourceListener
		}
		s.mu.Unlock()
		returned = true
	})
	return nil
}

func (s *nativeWorkerCallbackTransport) Address() string {
	if s == nil {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.address
}

// Close owns only this listener. Backend, database and caller TLS handles remain
// borrowed. A forced/unfinished shutdown returns an error, never a joined claim.
func (s *nativeWorkerCallbackTransport) Close() error {
	if s == nil {
		return nil
	}
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

func (s *nativeWorkerCallbackTransport) enter() bool {
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
func (s *nativeWorkerCallbackTransport) leave() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.active--
	if s.active == 0 {
		close(s.idle)
	}
}

func nativeWorkerCallbackTLSAuthenticated(c NativeWorkerProbeResourceListenerConfig, r *http.Request) bool {
	return r.TLS != nil && r.TLS.Version >= tls.VersionTLS13 && len(r.TLS.VerifiedChains) > 0 && len(r.TLS.PeerCertificates) > 0 && nativeProbeResourceLeaf(r.TLS.PeerCertificates[0], c.ClientURI, c.ClientLeafSHA256, x509.ExtKeyUsageClientAuth, time.Now())
}

// SDK framing is independent of TLS; stock scheduler callers have neither
// SDK Source/scope headers nor a writer bearer.
func nativeWorkerCallbackSDKAuthenticated(c NativeWorkerProbeResourceListenerConfig, r *http.Request) bool {
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
