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
)

func unsetHTTPIdentity(t *testing.T) {
	t.Helper()
	for _, key := range []string{"HTTP_TLS_CERT_FILE", "HTTP_TLS_KEY_FILE"} {
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
