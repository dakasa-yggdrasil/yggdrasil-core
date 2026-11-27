//go:build linux

package capacity

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func TestNativeWorkerRPCKubernetesRolesUseOriginalAuthenticatedTransport(t *testing.T) {
	roles := []string{"ensure_native_worker_pool", "observe_native_worker_pool", "observe_native_worker_phase"}
	for _, role := range roles {
		t.Run(role, func(t *testing.T) {
			var sends atomic.Int32
			client, cfg, _, raw := nativeRPCClientFixture(t, http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				sends.Add(1)
				if request.TLS == nil || len(request.TLS.VerifiedChains) == 0 || len(request.TLS.PeerCertificates) != 1 {
					t.Error("Kubernetes role bypassed actual mutual TLS")
				}
				var input model.AdapterExecuteIntegrationRequest
				if json.NewDecoder(request.Body).Decode(&input) != nil || input.Operation != role || input.Capability != role {
					t.Error("source-bound role changed on the original wire")
				}
				w.Header().Set("X-Yggdrasil-Source-Commit", strings.Repeat("c", 40))
				_, _ = io.WriteString(w, `{"status":"observed"}`)
			}), role)
			ctx := nativeRPCTestContext(t)
			if _, err := client.Call(ctx, cfg.BaseURL+"/rpc/execute", raw, 4096); err != nil || sends.Load() != 1 {
				t.Fatal("exact Kubernetes role could not use the real TLS transport", err)
			}
			for _, other := range []string{"ensure_native_worker", "observe_native_worker", "ensure_native_worker_pool", "observe_native_worker_pool", "observe_native_worker_phase"} {
				if other == role {
					continue
				}
				var input model.AdapterExecuteIntegrationRequest
				if json.Unmarshal(raw, &input) != nil {
					t.Fatal("invalid original fixture request")
				}
				input.Operation, input.Capability = other, other
				changed, err := json.Marshal(input)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = client.Call(ctx, cfg.BaseURL+"/rpc/execute", changed, 4096); err == nil || sends.Load() != 1 {
					t.Fatal("a Kubernetes role acquired another principal's operation", other, err)
				}
			}
		})
	}
}
