package message

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-sdk-go/rpc"
	"github.com/google/uuid"
)

// This exercises the actual private resolved SDK HTTP path, not a native
// mutation, PostgreSQL proof or production credential.
func TestCapacityNativePreRegistrationAbortPrivateWire(t *testing.T) {
	issued, forged := strings.Repeat("a", 64), strings.Repeat("b", 64)
	var received atomic.Int32
	t.Run("issued_exact_private_wire", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			received.Add(1)
			var wire model.AdapterExecuteIntegrationRequest
			if r.TLS == nil || r.Method != http.MethodPost || r.URL.Path != "/rpc/execute" || r.URL.RawQuery != "" || json.NewDecoder(r.Body).Decode(&wire) != nil || wire.Operation != capacity.DestroyNativeUnregisteredProtection || wire.Capability != wire.Operation || wire.Input["authority_token"] != issued || len(wire.Auth) != 0 || len(wire.Metadata) != 0 {
				t.Error("fresh private issued credential or fixed original route missing")
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			inner, err := json.Marshal(struct {
				OK   bool                                    `json:"ok"`
				Data model.AdapterExecuteIntegrationResponse `json:"data"`
			}{true, model.AdapterExecuteIntegrationResponse{Operation: wire.Operation, Capability: wire.Capability, Status: "observed", Output: map[string]any{"wire_only": true}}})
			if err != nil {
				t.Error("private fixture envelope unavailable")
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(rpc.Envelope{ContentType: "application/json", Body: inner})
		}))
		defer server.Close()
		transport, ok := server.Client().Transport.(*http.Transport)
		if !ok || transport.TLSClientConfig == nil || transport.TLSClientConfig.InsecureSkipVerify {
			t.Fatal("verified TLS fixture transport unavailable")
		}
		previous := http.DefaultTransport
		http.DefaultTransport = transport
		defer func() { http.DefaultTransport = previous; transport.CloseIdleConnections() }()
		no := false
		request := model.AdapterDestroyCapacityPodUnregisteredProtectionRequest{ExpectedPodUID: uuid.NewString(), ExpectedPodResourceVersion: "7", DryRun: &no}
		canonical, err := json.Marshal(request)
		if err != nil {
			t.Fatal("canonical private fixture unavailable")
		}
		before := append([]byte(nil), canonical...)
		request.AuthorityToken = forged // Sanitized input is never the credential authority.
		fields, err := nativeAbortPrivateInput(capacity.DestroyNativeUnregisteredProtection, request, issued)
		if err != nil {
			t.Fatal("private issued input unavailable")
		}
		defer delete(fields, "authority_token")
		im := model.Manifest{ID: uuid.New(), Kind: "integration_instance", Version: 1, Metadata: model.ManifestMetadata{Namespace: "fixture", Name: "abort"}}
		tm := model.Manifest{ID: uuid.New(), Kind: "integration_type", Version: 1, Metadata: model.ManifestMetadata{Namespace: "fixture", Name: "kubernetes-abort"}}
		is := model.IntegrationInstanceManifestSpec{Config: map[string]any{"base_url": server.URL}}
		ts := model.IntegrationTypeManifestSpec{Provider: "kubernetes", Capabilities: []string{"execute"}, ResourceTypes: []model.IntegrationResourceType{}, Adapter: model.IntegrationAdapterSpec{Transport: "http_json", Endpoints: model.IntegrationAdapterRoute{Execute: "/rpc/execute"}}}
		ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
		defer cancel()
		joined := false
		response, err := executeIntegrationThroughResolvedWithPolicy(ctx, nil, model.ExecuteIntegrationRequest{Operation: capacity.DestroyNativeUnregisteredProtection, Capability: capacity.DestroyNativeUnregisteredProtection, Input: fields}, im, is, tm, ts, 2*time.Second, integrationExecutionPolicy{detailFreeErrors: true, safeError: errCapacityBoundAssessment, requireExplicitResponse: true, nativeHTTP: &nativeAdapterHTTPPolicy{limit: 8192, parent: ctx, ownerDeadline: ctxDeadline(ctx), parentDeadline: ctxDeadline(ctx), originalReturn: func(value bool) { joined = value }}})
		if err != nil || !joined || received.Load() != 1 || response.Status != "observed" {
			t.Fatal("one original private resolved SDK wire was not joined")
		}
		public, err := json.Marshal(response)
		if err != nil || bytes.Contains(public, []byte(issued)) || bytes.Contains(public, []byte(forged)) || !bytes.Equal(before, canonical) || bytes.Contains(canonical, []byte(issued)) || bytes.Contains(canonical, []byte(forged)) {
			t.Fatal("credential escaped canonical/public fixture boundary")
		}
	})
	t.Run("forged_public_step_refused", func(t *testing.T) {
		var in capacityNativeAbortStepInput
		ordinary := map[string]any{"binding": map[string]any{}, "confirmation": "fixed"}
		if capacity.DecodeNativeCapacity(ordinary, &in) != nil {
			t.Fatal("closed input fixture unavailable")
		}
		ordinary["authority_token"] = forged
		if capacity.DecodeNativeCapacity(ordinary, &in) == nil {
			t.Fatal("caller supplied private credential through workflow input")
		}
	})
	t.Run("read_scrubs_forged_credential", func(t *testing.T) {
		fields, err := nativeAbortPrivateInput(capacity.ObserveNativeUnregisteredTerminal, map[string]any{"authority_token": forged}, "")
		if err != nil || fields["authority_token"] != nil {
			t.Fatal("caller credential reached read wire")
		}
	})
	t.Run("write_requires_issued_credential", func(t *testing.T) {
		if _, err := nativeAbortPrivateInput(capacity.DestroyNativeUnregisteredProtection, map[string]any{"authority_token": forged}, ""); err == nil {
			t.Fatal("forged input replaced server issued credential")
		}
	})
	t.Run("unsupported_operation_refused", func(t *testing.T) {
		if _, err := nativeAbortPrivateInput(capacity.DestroyNativePodProtection, map[string]any{}, issued); err == nil {
			t.Fatal("new private credential escaped its exact operation")
		}
	})
	t.Run("read_rejects_issued_credential", func(t *testing.T) {
		if _, err := nativeAbortPrivateInput(capacity.ObserveNativeUnregisteredTerminal, map[string]any{}, issued); err == nil {
			t.Fatal("issued mutation credential crossed read boundary")
		}
	})
	if received.Load() != 1 {
		t.Fatal("private refusal issued another original call")
	}
}
