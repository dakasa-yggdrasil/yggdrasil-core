//go:build recoveryfixture && !nativequalification

package repository

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// An isolated synthetic Guest returns one signed nonce over actual loopback
// mTLS. It has no provider credentials, process custody or production authority.
func labAcquireSyntheticV2Nonce(t *testing.T, owner *capacity.GuestRetirementV2OriginalOwner, coreKey ed25519.PrivateKey, request model.CapacityGuestRetirementRequestV2, enrollment model.CapacityGuestRetirementEnrollment, afterNonce func(*capacity.GuestOriginalHTTPClient)) {
	t.Helper()
	caPub, caKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "synthetic-lab-client-ca"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPub, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	clientPub, clientKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "synthetic-lab-core"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}, ca, clientPub, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(clientKey)
	if err != nil {
		t.Fatal(err)
	}
	clientCAs := x509.NewCertPool()
	clientCAs.AddCert(ca)
	var calls, writes atomic.Int64
	observer := ed25519.NewKeyFromSeed([]byte(strings.Repeat("o", 32)))
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.VerifiedChains) != 1 {
			http.Error(w, "synthetic client identity", http.StatusBadRequest)
			return
		}
		var got model.CapacityGuestRetirementRequestV2
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&got) != nil {
			http.Error(w, "synthetic request", http.StatusBadRequest)
			return
		}
		if r.Method == http.MethodPost && r.URL.Path == model.GuestRetirementV2WritePath {
			writes.Add(1)
			if got.Intent.RequestID != request.Intent.RequestID || got.Intent.AttemptID != request.Intent.AttemptID || capacity.ValidateGuestRetirementV2Request(got, enrollment, time.Now().UTC(), true) != nil {
				http.Error(w, "synthetic retirement", http.StatusBadRequest)
				return
			}
			// Only the synthetic endpoint receives this request. Drop the
			// original response after full receipt; do not invent Guest effect.
			hijacker, ok := w.(http.Hijacker)
			if !ok {
				http.Error(w, "synthetic transport", http.StatusInternalServerError)
				return
			}
			conn, _, hijackErr := hijacker.Hijack()
			if hijackErr != nil {
				return
			}
			_ = conn.Close()
			return
		}
		calls.Add(1)
		if r.Method != http.MethodGet || r.URL.Path != model.GuestRetirementV2NoncePath || capacity.GuestRetirementSHA(got.Intent) != capacity.GuestRetirementSHA(request.Intent) || capacity.ValidateGuestRetirementV2Preflight(got, enrollment, time.Now().UTC()) != nil {
			http.Error(w, "synthetic preflight", http.StatusBadRequest)
			return
		}
		i := got.Intent
		nonce := model.CapacityGuestRetirementNonceV2{Schema: capacity.GuestRetirementV2NonceSchema, RequestID: i.RequestID, AttemptID: i.AttemptID, PreflightSHA256: capacity.GuestRetirementV2PreflightSHA(i), EnrollmentSHA256: capacity.GuestRetirementSHA(enrollment), Actor: enrollment.Statement.Actor, Runtime: enrollment.Statement.Runtime, WriterRosterSHA256: enrollment.Statement.WriterRosterSHA256, NonceSHA256: strings.Repeat("2", 64), IssuedMonotonicNS: 1000000000, ExpiresMonotonicNS: 1000000000 + int64(i.OriginalDeadline.Sub(i.IssuedAt))}
		signature, signErr := capacity.GuestLifecycleSignature(observer, nonce)
		if signErr != nil {
			http.Error(w, "synthetic signature", http.StatusInternalServerError)
			return
		}
		nonce.Signature = signature
		raw, err := json.Marshal(nonce)
		if err != nil {
			http.Error(w, "synthetic encoding", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(raw)
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: clientCAs}
	server.StartTLS()
	defer server.Close()
	host, _, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		t.Fatal("synthetic server must be loopback")
	}
	root := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	key := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	client, err := capacity.NewGuestOriginalHTTPClient(model.CapacityGuestRetirementMemberBinding{Origin: server.URL}, root, cert, key)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err = owner.AcquireNonce(client, coreKey, request, enrollment); err != nil {
		t.Fatal("actual loopback mTLS nonce", err)
	}
	if err = owner.AcquireNonce(client, coreKey, request, enrollment); err == nil || calls.Load() != 1 {
		t.Fatal("nonce replay or duplicate HTTP")
	}
	afterNonce(client)
	if calls.Load() != 1 || writes.Load() != 1 {
		t.Fatal("synthetic HTTP replay", calls.Load(), writes.Load())
	}
}
