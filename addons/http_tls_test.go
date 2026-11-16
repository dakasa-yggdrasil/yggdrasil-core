package addons

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/controllers/httpapi"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/coreprocess"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/runtime"
)

func unsetHTTPIdentity(t *testing.T) {
	t.Helper()
	for _, key := range []string{"HTTP_TLS_CERT_FILE", "HTTP_TLS_KEY_FILE", "HTTP_TLS_SECONDARY_ADDR"} {
		t.Setenv(key, "")
		if err := os.Unsetenv(key); err != nil {
			t.Fatal(err)
		}
	}
}

func TestHTTPTLSExplicitIdentityAdmission(t *testing.T) {
	for _, mode := range []string{"absent_preserves_http", "certificate_only", "key_only", "blank", "relative", "path_alias", "whitespace", "missing_private_file"} {
		t.Run(mode, func(t *testing.T) {
			unsetHTTPIdentity(t)
			privatePath := filepath.Join(t.TempDir(), "private_fixture_identity")
			switch mode {
			case "certificate_only":
				t.Setenv("HTTP_TLS_CERT_FILE", privatePath)
			case "key_only":
				t.Setenv("HTTP_TLS_KEY_FILE", privatePath)
			case "blank":
				t.Setenv("HTTP_TLS_CERT_FILE", "")
				t.Setenv("HTTP_TLS_KEY_FILE", "")
			case "relative":
				t.Setenv("HTTP_TLS_CERT_FILE", "identity.crt")
				t.Setenv("HTTP_TLS_KEY_FILE", "identity.key")
			case "path_alias":
				t.Setenv("HTTP_TLS_CERT_FILE", filepath.Dir(privatePath)+"/../identity.crt")
				t.Setenv("HTTP_TLS_KEY_FILE", privatePath)
			case "whitespace":
				t.Setenv("HTTP_TLS_CERT_FILE", " "+privatePath)
				t.Setenv("HTTP_TLS_KEY_FILE", privatePath)
			case "missing_private_file":
				t.Setenv("HTTP_TLS_CERT_FILE", privatePath)
				t.Setenv("HTTP_TLS_KEY_FILE", privatePath)
			}
			cfg, err := httpTLSConfigFromEnv()
			if mode == "absent_preserves_http" {
				if err != nil || cfg != nil {
					t.Fatal("absent opt-in changed original HTTP")
				}
				return
			}
			if err == nil || cfg != nil {
				t.Fatal("malformed TLS identity fell back to a transport")
			}
			for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
				if strings.Contains(fmt.Sprintf(format, err), privatePath) {
					t.Fatal("mounted private identity path leaked")
				}
			}
			t.Setenv("YGGDRASIL_OIDC_CLIENTS_FILE", "")
			t.Setenv("YGGDRASIL_OIDC_ISSUER", "")
			if _, ok := bootstrapHTTP(t.Context(), nil).(httpTLSConfigurationError); !ok {
				t.Fatal("TLS opt-in was not refused before HTTP addon database access and OIDC/API effects")
			}
		})
	}
}

func httpTLSNativeIdentity(t *testing.T) (*tls.Config, *x509.CertPool) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identity := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true, IsCA: true}
	cert, err := x509.CreateCertificate(rand.Reader, identity, identity, public, private)
	if err != nil {
		t.Fatal(err)
	}
	key, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "identity.crt"), filepath.Join(dir, "identity.key")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert})
	if os.WriteFile(certPath, certPEM, 0600) != nil || os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0600) != nil {
		t.Fatal("native mounted test identity unavailable")
	}
	t.Setenv("HTTP_TLS_CERT_FILE", certPath)
	t.Setenv("HTTP_TLS_KEY_FILE", keyPath)
	cfg, err := httpTLSConfigFromEnv()
	if err != nil || cfg == nil || cfg.MinVersion != tls.VersionTLS12 || len(cfg.Certificates) != 1 {
		t.Fatal("actual mounted TLS identity was not loaded")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certPEM) {
		t.Fatal("native test root unavailable")
	}
	return cfg, roots
}

func TestHTTPTLSOriginalListenerReadCloseShutdown(t *testing.T) {
	workerClosedAddonSet(t)
	productionHTTPOriginalDrain(t)
	for _, mode := range []string{"absent_preserves_http", "explicit_verified_tls"} {
		t.Run(mode, func(t *testing.T) {
			unsetHTTPIdentity(t)
			var cfg *tls.Config
			var roots *x509.CertPool
			scheme := "http"
			if mode == "explicit_verified_tls" {
				cfg, roots = httpTLSNativeIdentity(t)
				scheme = "https"
			} else {
				var configErr error
				cfg, configErr = httpTLSConfigFromEnv()
				if configErr != nil || cfg != nil {
					t.Fatal("absent opt-in changed original HTTP")
				}
			}
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			var calls atomic.Int64
			expectedBody := "original " + scheme + " handler"
			server := &http.Server{Addr: listener.Addr().String(), TLSConfig: cfg, ReadHeaderTimeout: time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if (r.TLS != nil) != (cfg != nil) {
					t.Error("actual original listener transport differs from configured mode")
				}
				calls.Add(1)
				_, _ = io.WriteString(w, expectedBody)
			})}
			returned := make(chan error, 1)
			// Exercise the SAME helper called by the original production bootstrap.
			// Calling ServeTLS directly would not detect a regression to plaintext.
			go func() { returned <- serveConfiguredHTTP(server, listener) }()
			joined := false
			t.Cleanup(func() {
				_ = server.Close()
				_ = listener.Close()
				if !joined {
					<-returned
				}
			})
			owner, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport}
			request, err := http.NewRequestWithContext(owner, http.MethodGet, scheme+"://"+listener.Addr().String()+"/healthz", nil)
			if err != nil {
				t.Fatal(err)
			}
			response, err := client.Do(request)
			if err != nil {
				t.Fatal("original configured transport caller did not return")
			}
			body, readErr := io.ReadAll(io.LimitReader(response.Body, 1025))
			closeErr := response.Body.Close()
			if readErr != nil || closeErr != nil || response.StatusCode != http.StatusOK || string(body) != expectedBody || calls.Load() != 1 {
				t.Fatal("original handler or original Do/Read/Close unavailable")
			}
			if cfg == nil {
				if response.TLS != nil {
					t.Fatal("absent opt-in changed original plaintext response")
				}
			} else if response.TLS == nil || response.TLS.Version < tls.VersionTLS12 || len(response.TLS.VerifiedChains) == 0 {
				t.Fatal("actual verified TLS identity unavailable")
			}
			if err := server.Shutdown(owner); err != nil {
				t.Fatal("original listener shutdown did not return")
			}
			if err := <-returned; !errors.Is(err, http.ErrServerClosed) {
				t.Fatal("original configured Serve owner did not return")
			}
			joined = true
		})
	}
}

func workerClosedAddonSet(t *testing.T) {
	t.Helper()
	want := map[string]bool{"observability": true, "boot-validation": true, "postgres": true, "rabbitmq": true, "integration_surface_sync": true, "http": true}
	mu.RLock()
	entries := append([]registeredAddon(nil), registry...)
	mu.RUnlock()
	selected := map[string]bool{}
	for _, entry := range entries {
		if coreprocess.AllowedAddon(coreprocess.APIWorker, entry.name) {
			selected[entry.name] = true
			if !want[entry.name] {
				t.Fatal("background authority addon entered worker", entry.name)
			}
		}
		if !coreprocess.AllowedAddon(coreprocess.Authority, entry.name) {
			t.Fatal("default authority lost existing addon", entry.name)
		}
	}
	if len(selected) != len(want) || coreprocess.AllowedAddon(coreprocess.APIWorker, "future-unreviewed-addon") {
		t.Fatal("API startup set is not closed", selected)
	}
	for name := range want {
		if !selected[name] {
			t.Fatal("required worker startup dependency absent", name)
		}
	}
	previous, present := os.LookupEnv(coreprocess.RoleEnv)
	defer func() {
		if present {
			_ = os.Setenv(coreprocess.RoleEnv, previous)
		} else {
			_ = os.Unsetenv(coreprocess.RoleEnv)
		}
	}()
	for _, bad := range []string{"API_WORKER", "api_worker ", "unknown"} {
		t.Setenv(coreprocess.RoleEnv, bad)
		// nil runtime makes any bootstrap/resource access a hard failure. An
		// invalid role must return before even observability/DB/consumer I/O.
		if err := Apply(t.Context(), nil); err == nil {
			t.Fatal("invalid process role reached startup")
		}
	}
}

func productionHTTPOriginalDrain(t *testing.T) {
	t.Helper()
	owner, err := httpapi.NewOriginalWorkflowOwners(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	parent, finish, err := owner.Begin()
	if err != nil || parent != t.Context() {
		t.Fatal("original parent changed", err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var callbacks atomic.Int32
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callbacks.Add(1)
		w.WriteHeader(http.StatusOK)
	})}
	returned := make(chan error, 1)
	go func() { returned <- server.Serve(listener) }()
	t.Cleanup(func() { finish(); _ = server.Close(); _ = listener.Close() })
	app := runtime.New("original-workflow-drain-source")
	app.RegisterDrainer(owner.Seal)
	dependentClosed := false
	app.RegisterCloser(func(context.Context) error { dependentClosed = true; return nil })
	// Inspect the original owner from the actual closer ordering, rather than
	// calling Seal only in the test and assuming runtime uses it in production.
	app.RegisterCloser(func(ctx context.Context) error {
		if owner.AdmissionOpen() || dependentClosed {
			t.Fatal("admission/dependency shutdown order changed")
		}
		if parent.Err() != nil {
			t.Fatal("drain canceled original work")
		}
		canceled, cancel := context.WithCancel(ctx)
		cancel()
		if err := shutdownOwnedHTTPServers(canceled, owner, []*http.Server{server}); !errors.Is(err, context.Canceled) {
			t.Fatal("pending original return became shutdown success", err)
		}
		response, err := http.Get("http://" + listener.Addr().String())
		if err != nil {
			t.Fatal("original callback listener closed before return", err)
		}
		_, readErr := io.ReadAll(response.Body)
		closeErr := response.Body.Close()
		if readErr != nil || closeErr != nil || response.StatusCode != http.StatusOK || callbacks.Load() != 1 {
			t.Fatal("original descendant did not return")
		}
		finish()
		finish()
		return shutdownOwnedHTTPServers(ctx, owner, []*http.Server{server})
	})
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if err := app.Shutdown(ctx); err != nil || !dependentClosed {
		t.Fatal("actual returns did not join before dependencies", err)
	}
	if err := <-returned; !errors.Is(err, http.ErrServerClosed) {
		t.Fatal("listener owner did not return", err)
	}
}

func TestHTTPSecondaryTLSAdmissionBeforeDatabase(t *testing.T) {
	for _, address := range []string{"", " :9443", ":09443", ":0", ":65536", "localhost:9443", "[fe80::1%lo0]:9443", ":9080", "127.0.0.1:9080", "127.000.0.1:9443", "[0:0:0:0:0:0:0:1]:9443"} {
		t.Run(address, func(t *testing.T) {
			cfg, _ := httpTLSNativeIdentity(t)
			t.Setenv("HTTP_TLS_SECONDARY_ADDR", address)
			if _, err := httpTLSSecondaryAddrFromEnv(cfg, ":9080"); err == nil {
				t.Fatal("invalid or conflicting secondary accepted")
			}
			t.Setenv("YGGDRASIL_OIDC_CLIENTS_FILE", "")
			t.Setenv("YGGDRASIL_OIDC_ISSUER", "")
			t.Setenv("HTTP_ADDR", ":9080")
			if _, ok := bootstrapHTTP(t.Context(), nil).(httpTLSConfigurationError); !ok {
				t.Fatal("secondary validation did not precede database access")
			}
		})
	}
	for _, address := range []string{":9443", "127.0.0.1:9443", "[::1]:9443"} {
		t.Run(address, func(t *testing.T) {
			cfg, _ := httpTLSNativeIdentity(t)
			t.Setenv("HTTP_TLS_SECONDARY_ADDR", address)
			got, err := httpTLSSecondaryAddrFromEnv(cfg, ":9080")
			if err != nil || got != address {
				t.Fatal("canonical secondary refused")
			}
			if _, err := httpTLSSecondaryAddrFromEnv(nil, ":9080"); err == nil {
				t.Fatal("secondary accepted without mounted identity")
			}
		})
	}
}

func TestHTTPSecondaryTLSOriginalSharedHandler(t *testing.T) {
	cfg, roots := httpTLSNativeIdentity(t)
	var calls atomic.Int64
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		_, _ = fmt.Fprintf(w, "same owner %d", n)
	})
	servers := configuredHTTPServers("127.0.0.1:0", "127.0.0.1:0", handler, cfg)
	if len(servers) != 2 || servers[0].TLSConfig != nil || servers[1].TLSConfig != cfg {
		t.Fatal("primary HTTP and secondary TLS configuration differs")
	}
	listeners, err := listenHTTPServers(servers)
	if err != nil {
		t.Fatal(err)
	}
	returns := make([]chan error, 2)
	for i, server := range servers {
		returns[i] = make(chan error, 1)
		go func() { returns[i] <- serveConfiguredHTTP(server, listeners[i]) }()
	}
	joined := false
	t.Cleanup(func() {
		for i, server := range servers {
			_ = server.Close()
			_ = listeners[i].Close()
		}
		if !joined {
			for _, returned := range returns {
				<-returned
			}
		}
	})
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport}
	for i, scheme := range []string{"http", "https"} {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, scheme+"://"+listeners[i].Addr().String()+"/healthz", nil)
		if err != nil {
			t.Fatal(err)
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		body, readErr := io.ReadAll(io.LimitReader(response.Body, 1025))
		closeErr := response.Body.Close()
		if readErr != nil || closeErr != nil || response.StatusCode != 200 || string(body) != fmt.Sprintf("same owner %d", i+1) {
			t.Fatal("same handler original response unavailable")
		}
		if i == 0 && response.TLS != nil {
			t.Fatal("primary HTTP changed")
		}
		if i == 1 && (response.TLS == nil || len(response.TLS.VerifiedChains) == 0) {
			t.Fatal("secondary TLS identity unverified")
		}
	}
	if calls.Load() != 2 {
		t.Fatal("handler owner state was duplicated")
	}
	if err := shutdownHTTPServers(ctx, servers); err != nil {
		t.Fatal(err)
	}
	for _, returned := range returns {
		if err := <-returned; !errors.Is(err, http.ErrServerClosed) {
			t.Fatal("original server did not return")
		}
	}
	joined = true
}

func TestHTTPSecondaryBindFailureClosesPrimary(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	primary, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	primaryAddr := primary.Addr().String()
	_ = primary.Close()
	servers := configuredHTTPServers(primaryAddr, occupied.Addr().String(), http.NotFoundHandler(), &tls.Config{MinVersion: tls.VersionTLS12})
	if listeners, err := listenHTTPServers(servers); err == nil || listeners != nil {
		t.Fatal("partial bind accepted")
	}
	rebound, err := net.Listen("tcp", primaryAddr)
	if err != nil {
		t.Fatal("failed secondary left primary socket bound")
	}
	_ = rebound.Close()
}
