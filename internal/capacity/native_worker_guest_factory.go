package capacity

import (
	"bytes"
	"context"
	"encoding/json"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func (f *NativeWorkerPrivateFactory) MatchesGuestNetwork(n model.CapacityNativeWorkerNetworkTemplate, digest string) bool {
	if f == nil || f.nativeWorkerPrivateFactoryState == nil {
		return false
	}
	f.mu.RLock()
	defer f.mu.RUnlock()
	return !f.closed && f.guest != nil && f.guest.network == n && f.guest.config.NetworkTemplateSHA256 == digest
}

// v2 private material is opt-in through the durable public Execution pin. It
// does not change the canonical public Launch v1 or the nil-config v1 bytes.
func (g *nativeGuestReadIdentity) renderInput(a model.CapacityNativeWorkerAttempt, launch, material []byte, capability, source string) ([]byte, error) {
	if g == nil || a.Execution.GuestIdentityPolicySHA256 != g.policySHA256 {
		return nil, errNativeGuestRead
	}
	cert, err := g.derive(a, launch, source)
	if err != nil {
		return nil, errNativeGuestRead
	}
	defer cert.close()
	clientCert, err := g.deriveClient(a, launch, source)
	if err != nil {
		return nil, errNativeGuestRead
	}
	defer clientCert.close()
	if !time.Now().UTC().Before(cert.notAfter) {
		return nil, errNativeGuestRead
	}
	tlsMaterial, err := json.Marshal(struct {
		Certificate string `json:"server_certificate_pem"`
		Key         string `json:"server_private_key_pem"`
		CA          string `json:"core_client_ca_pem"`
		ClientPin   string `json:"core_client_certificate_sha256"`
	}{string(cert.certificatePEM), string(cert.privateKeyPEM), string(g.issuerPEM), clientCert.fingerprint})
	if err != nil {
		return nil, errNativeGuestRead
	}
	defer nativePrivateWipe(tlsMaterial)
	network, err := json.Marshal(g.network)
	if err != nil {
		return nil, errNativeGuestRead
	}
	return json.Marshal(struct {
		Schema   string          `json:"schema"`
		Launch   json.RawMessage `json:"launch"`
		SHA      string          `json:"launch_sha256"`
		Material json.RawMessage `json:"material"`
		URL      string          `json:"operator_capability_url"`
		Network  json.RawMessage `json:"network_template"`
		TLS      json.RawMessage `json:"guest_read_tls"`
	}{"native_worker_private_render_v2", launch, a.LaunchSHA256, material, capability, network, tlsMaterial})
}

// The factory handle and all its copies share the original Close fence. The
// only destination is this Attempt's allocated overlay IPv4 at fixed port9445.
func (f *NativeWorkerPrivateFactory) ReadGuestWitness(ctx context.Context, a model.CapacityNativeWorkerAttempt, stored json.RawMessage) (model.CapacityNativeWorkerGuestWitness, error) {
	var zero model.CapacityNativeWorkerGuestWitness
	if f == nil || f.nativeWorkerPrivateFactoryState == nil || ctx == nil || ctx.Err() != nil {
		return zero, errNativeGuestRead
	}
	f.mu.RLock()
	defer f.mu.RUnlock()
	if f.closed || f.guest == nil || a.Execution.GuestIdentityPolicySHA256 != f.guest.policySHA256 {
		return zero, errNativeGuestRead
	}
	prepared, key, err := f.prepare(a)
	defer nativePrivateWipe(key)
	if err != nil || !bytes.Equal(stored, prepared.PublicJSON) || nativePrivateSHA(stored) != a.LaunchSHA256 {
		return zero, errNativeGuestRead
	}
	return f.guest.read(ctx, a, stored, f.config.SystemBuildSource, nil)
}
