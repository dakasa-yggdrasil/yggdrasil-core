//go:build linux && nativequalification

package capacitynativeqemu

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
)

func TestSourceFailureCleanupReceiptStages(t *testing.T) {
	for _, tc := range []struct{ name, want string }{
		{"read_refused", "prepare_receipt_read"},
		{"unsettled", "prepare_receipt_state"},
		{"transport_incomplete", "prepare_receipt_transport"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			grantID, workflow := uuid.NewString(), uuid.New()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if tc.name == "read_refused" {
					w.WriteHeader(http.StatusServiceUnavailable)
					return
				}
				receipt := model.CapacityMutationReceipt{Grant: model.CapacityMutationGrant{GrantID: grantID, State: "settled"}}
				if tc.name == "unsettled" {
					receipt.Grant.State = "confirmed"
				}
				if err := json.NewEncoder(w).Encode(receipt); err != nil {
					t.Error(err)
				}
			}))
			defer server.Close()
			realm := Realm{Request: SourceRequest{NativeCase: "source_live_failed_floor_recovery"}, CoreOrigin: server.URL, Client: server.Client(), originals: map[int]IndependentReturn{2: {}}, disks: map[int]OriginalDisk{2: {}}}
			store := repository.CapacityStore{WorkflowID: workflow}
			policy := model.Manifest{Metadata: model.ManifestMetadata{Namespace: "qualification"}}
			pre := model.CapacityGuestOriginalProvisioningPreregistration{Slot: 2, WorkflowID: workflow.String(), OriginalCreateGrantID: grantID, CoreSourceCommit: capacity.CurrentGuestCoreSource()}
			key := make(ed25519.PrivateKey, ed25519.PrivateKeySize)
			stage := "unknown"
			_, _, observed := realm.PrepareSourceFailureCleanupDiagnostic(context.Background(), store, policy, pre, "", "", key, &stage)
			_, _, original := realm.PrepareSourceFailureCleanup(context.Background(), store, policy, pre, "", "", key)
			if observed != ErrOriginalUnknown || original != observed || stage != tc.want {
				t.Fatalf("diagnostic changed receipt refusal or stage: %q", stage)
			}
		})
	}
}
