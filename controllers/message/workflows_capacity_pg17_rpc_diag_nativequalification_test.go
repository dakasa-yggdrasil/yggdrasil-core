//go:build linux && nativequalification

package message

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	q "github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacitynativeqemu"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacityqualification"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-sdk-go/rpc"
	"github.com/google/uuid"
)

func TestPG17ReadClientScopeAndRetention(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(q.SlotDirectory(dir, 2), 0700); err != nil {
		t.Fatal(err)
	}
	prior := originalGuestNativeRealm
	t.Cleanup(func() { originalGuestNativeRealm = prior })
	realm := &q.Realm{PrivateDirectory: dir}
	realm.Request.NativeCase = "positive_original_lifecycle"
	originalGuestNativeRealm = realm
	path := filepath.Join(q.SlotDirectory(dir, 2), "pg17-read-diagnostic-client.json")
	unmarked := guestPG17ReadDiagnosticContext(context.Background(), "capacity.observe_vm_inventory", "observe_servers")
	guestPG17TransportStage(unmarked, "contract_request")
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("unrelated operation recorded diagnostic", err)
	}
	marked := guestPG17ReadDiagnosticContext(context.Background(), "capacity.confirm_native_mutation", "observe_servers")
	guestPG17TransportStage(marked, "contract_request")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var row map[string]any
	if json.Unmarshal(b, &row) != nil || len(row) != 3 || row["origin"] != "client" || row["stage"] != "contract_request" {
		t.Fatalf("unexpected fixed diagnostic %v", row)
	}
	guestPG17TransportStage(marked, "rpc_response")
	b2, err := os.ReadFile(path)
	if err != nil || string(b) != string(b2) {
		t.Fatal("original diagnostic was replaced")
	}
}

type pg17FailingTransport struct {
	calls    int
	response []byte
	failure  error
}

func (s *pg17FailingTransport) Consume(rpc.ConsumerConfig) (rpc.Subscription, error) {
	return nil, errors.New("unexpected consume")
}
func (s *pg17FailingTransport) Publish(context.Context, rpc.Request) error {
	return errors.New("unexpected publish")
}
func (s *pg17FailingTransport) Close() error { return nil }
func (s *pg17FailingTransport) Request(ctx context.Context, req rpc.Request) (rpc.Reply, error) {
	s.calls++
	var wire model.AdapterExecuteIntegrationRequest
	if req.Endpoint != "qualification.original.execute" || capacity.DecodeGuestLifecycle(req.Body, &wire) != nil || wire.Operation != capacity.VMObserveServer || wire.Capability != capacity.VMObserveServer || len(wire.Auth) != 0 || len(wire.Metadata) != 0 {
		return rpc.Reply{}, errors.New("invalid synthetic request")
	}
	if s.failure != nil {
		return rpc.Reply{}, s.failure
	}
	return rpc.Reply{Body: s.response, ContentType: "application/json"}, nil
}

// Exercises the actual transport/codec path with a local in-memory transport.
// No broker, provider, QEMU or Native qualification is implied.
func TestPG17ReadTransportFailureStages(t *testing.T) {
	prior := originalGuestNativeRealm
	t.Cleanup(func() { originalGuestNativeRealm = prior })
	for _, tc := range []struct {
		name, stage string
		body        []byte
		failure     error
	}{
		{"remote_refusal", "rpc_response", []byte(`{"ok":false,"error":{"code":"synthetic","message":"synthetic"}}`), nil},
		{"roundtrip_failure", "rpc_roundtrip", nil, errors.New("synthetic transport failure")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Mkdir(q.SlotDirectory(dir, 2), 0700); err != nil {
				t.Fatal(err)
			}
			realm := &q.Realm{PrivateDirectory: dir}
			realm.Request.NativeCase = "positive_original_lifecycle"
			originalGuestNativeRealm = realm
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			marked := guestPG17ReadDiagnosticContext(ctx, "capacity.confirm_native_mutation", capacity.VMObserveServer)
			desc, err := capacityqualification.NativeDescribe()
			if err != nil {
				t.Fatal(err)
			}
			raw, err := json.Marshal(desc)
			if err != nil {
				t.Fatal(err)
			}
			var spec model.IntegrationTypeManifestSpec
			if json.Unmarshal(raw, &spec) != nil {
				t.Fatal("invalid describe")
			}
			tid, iid := uuid.New(), uuid.New()
			typeRef := model.ManifestReference{ID: tid, Kind: "integration_type", Namespace: "synthetic-ci", Name: "qemu", Version: 1}
			instanceRef := model.ManifestReference{ID: iid, Kind: "integration_instance", Namespace: "synthetic-ci", Name: "qemu", Version: 1}
			instanceSpec := model.IntegrationInstanceManifestSpec{TypeRef: model.ManifestSelector{ManifestID: tid.String()}}
			request := model.AdapterExecuteIntegrationRequest{Operation: capacity.VMObserveServer, Capability: capacity.VMObserveServer, Input: map[string]any{"profile": "native-qemu", "slot": 2, "grant_id": uuid.NewString(), "expected_resource_id": uuid.NewString(), "expected_resource_created_at": "2026-10-28T13:58:33Z"}, Integration: model.AdapterExecuteIntegrationContext{Type: typeRef, TypeSpec: spec, Instance: instanceRef, InstanceSpec: instanceSpec}}
			fake := &pg17FailingTransport{response: tc.body, failure: tc.failure}
			client := newAdapterTransportClient(fake)
			var response model.AdapterExecuteIntegrationResponse
			policy := adapterCallPolicy{detailFreeErrors: true, native: &nativeAdapterHTTPPolicy{limit: 2 << 20, parent: ctx}}
			err = client.callWithPolicy(marked, integrationExecuteContract, spec, instanceSpec, "execute", request, &response, policy)
			if err == nil || fake.calls != 1 || !reflect.DeepEqual(response, model.AdapterExecuteIntegrationResponse{}) {
				t.Fatalf("refusal path changed: calls=%d err=%v", fake.calls, err)
			}
			if tc.failure != nil && !errors.Is(err, tc.failure) {
				t.Fatalf("original error cause lost: %v", err)
			}
			b, err := os.ReadFile(filepath.Join(q.SlotDirectory(dir, 2), "pg17-read-diagnostic-client.json"))
			if err != nil {
				t.Fatal(err)
			}
			var row map[string]any
			if json.Unmarshal(b, &row) != nil || len(row) != 3 || row["origin"] != "client" || row["stage"] != tc.stage {
				t.Fatalf("incorrect fixed diagnostic %v", row)
			}
		})
	}
}
