package nativeworkerprobe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime/debug"
	"time"

	safego "github.com/dakasa-yggdrasil/yggdrasil-core/internal/goroutine"
)

func compiledSource() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	source, clean := "", false
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			source = s.Value
		case "vcs.modified":
			clean = s.Value == "false"
		}
	}
	if !clean || !sourcePattern.MatchString(source) {
		return ""
	}
	return source
}

func emptyOriginalRequest(r *http.Request) bool {
	if r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
		return false
	}
	if r.Body == nil {
		return r.Context().Err() == nil
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 1))
	closeErr := r.Body.Close()
	return err == nil && closeErr == nil && len(raw) == 0 && r.Context().Err() == nil
}

func (e *engine) handler(ctx context.Context, source string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Yggdrasil-Source-Commit", source)
		// Identity is checked before any body, route action or loopback read.
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, "probe authentication required", http.StatusUnauthorized)
			return
		}
		leaf := r.TLS.PeerCertificates[0]
		if len(r.TLS.VerifiedChains) == 0 || sha(leaf.Raw) != e.material.config.ControllerLeafSHA256 || !leafRole(leaf, x509.ExtKeyUsageClientAuth, time.Now()) {
			http.Error(w, "probe principal refused", http.StatusForbidden)
			return
		}
		if ctx.Err() != nil || !time.Now().Before(e.material.config.HardNotAfter) {
			http.Error(w, "probe expired", http.StatusGone)
			return
		}
		if r.URL.RawPath != "" || r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.Fragment != "" || !emptyOriginalRequest(r) {
			http.Error(w, "closed probe request required", http.StatusBadRequest)
			return
		}
		var out any
		status := http.StatusOK
		switch {
		case r.Method == http.MethodGet && r.URL.Path == ReportPath:
			out = e.report(source)
		case r.Method == http.MethodGet && r.URL.Path == StartupPath:
			if e.material.config.Identity.Role != "candidate" || e.material.config.Startup == nil {
				http.Error(w, "startup role refused", http.StatusForbidden)
				return
			}
			out = e.inspectStartup(r.Context(), source)
		case r.Method == http.MethodPost && (r.URL.Path == InitialPath || r.URL.Path == FinalPath):
			name := "initial"
			if r.URL.Path == FinalPath {
				name = "final"
			}
			if !e.start(ctx, name) {
				http.Error(w, "probe phase already started or unavailable", http.StatusConflict)
				return
			}
			status, out = http.StatusAccepted, e.report(source)
		default:
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(out)
	})
}

// Run owns the actual sockets and joins their original shutdown returns. It
// accepts no workflow, environment destination, URL or command-line operand.
func Run(parent context.Context) error {
	if parent == nil || parent.Err() != nil {
		return ErrUnavailable
	}
	source := compiledSource()
	if source == "" {
		return ErrUnavailable
	}
	if waitForProbeProjection(parent, ConfigPath) != nil {
		return ErrUnavailable
	}
	m, err := loadMaterial(filepath.Dir(ConfigPath), source, time.Now().UTC())
	if err != nil {
		return ErrUnavailable
	}
	return serve(parent, m, source)
}

// An initially absent optional Secret can need the normal kubelet remount
// interval: Kubernetes 1.32 defaults to 60s with 0.5 resync jitter. This fixed 120s
// startup bound covers that normal window without a waiter or cadence override.
// It does not renew the original config lifetime: once the file appears,
// loadMaterial immediately validates its original NotBefore/HardNotAfter and
// every private byte. Malformed/present material is never retried here.
func waitForProbeProjection(parent context.Context, path string) error {
	if parent == nil || parent.Err() != nil {
		return ErrUnavailable
	}
	startup, cancel := context.WithTimeout(parent, 120*time.Second)
	defer cancel()
	for {
		if startup.Err() != nil {
			return ErrUnavailable
		}
		_, err := os.Stat(path)
		if err == nil {
			return nil
		}
		if !os.IsNotExist(err) {
			return ErrUnavailable
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-startup.Done():
			timer.Stop()
			return ErrUnavailable
		case <-timer.C:
		}
	}
}

func serve(parent context.Context, m *material, source string) error {
	e, ctx, err := newEngine(parent, m)
	if err != nil {
		m.close()
		return ErrUnavailable
	}
	listener, err := net.Listen("tcp4", net.JoinHostPort(m.config.Identity.PodIPv4, "9446"))
	if err != nil {
		_ = e.close()
		return ErrUnavailable
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{m.server}, ClientCAs: m.clientCA, ClientAuth: tls.VerifyClientCertIfGiven}
	server := &http.Server{Handler: e.handler(ctx, source), ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 3 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 8192, ErrorLog: log.New(io.Discard, "", 0), BaseContext: func(net.Listener) context.Context { return ctx }}
	returned := make(chan error, 1)
	safego.SafeGo("native_probe_http", func() {
		completed := false
		defer func() {
			if !completed {
				_ = recover()
				returned <- ErrUnavailable
			}
		}()
		returned <- server.Serve(tls.NewListener(listener, tlsConfig))
		completed = true
	})
	var original error
	joined := false
	select {
	case original = <-returned:
		joined = true
	case <-ctx.Done():
	}
	// A separately finite cleanup owns all sockets even after the work expires.
	shutdown, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	shutdownErr := server.Shutdown(shutdown)
	if shutdownErr != nil {
		_ = server.Close()
	}
	if !joined {
		select {
		case original = <-returned:
		case <-shutdown.Done():
			_ = e.close()
			return ErrUnavailable
		}
	}
	closeErr := e.close()
	if shutdownErr != nil || closeErr != nil || original != nil && !errors.Is(original, http.ErrServerClosed) {
		return ErrUnavailable
	}
	return nil
}
