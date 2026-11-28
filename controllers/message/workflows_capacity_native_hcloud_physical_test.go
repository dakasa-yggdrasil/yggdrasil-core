package message

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

func TestNativeHCloudPhysicalReplyKeepsTheActualProviderWire(t *testing.T) {
	b := model.CapacityNativeWorkerPhysicalReadBinding{Profile: "aws-looking-profile", Provider: "hetzner", Region: "hel1", Adapter: model.CapacityMarketAdapterBinding{ManifestID: uuid.NewString(), Version: 2, Checksum: strings.Repeat("a", 64), IntegrationTypeID: uuid.NewString(), TypeChecksum: strings.Repeat("b", 64)}, BindingName: "separate-hcloud-read", SourceCommit: strings.Repeat("c", 40), ScopeSHA256: strings.Repeat("d", 64), Capability: capacity.ObserveNativeWorkerPhysical, HCloudScope: &model.CapacityNativeWorkerHCloudProjectScope{DeclaredProjectID: "reviewed-project"}}
	request := model.CapacityNativeWorkerObservationRequest{BindingName: b.BindingName, AttemptID: uuid.NewString(), ResourceID: "43210", LaunchSHA256: strings.Repeat("e", 64)}
	o := model.CapacityNativeWorkerHCloudPhysicalObservation{Schema: "hcloud_native_worker_physical_observation_v1", SourceCommit: b.SourceCommit, Adapter: b.Adapter, BindingName: b.BindingName, BindingScopeSHA256: b.ScopeSHA256, Requested: request,
		ProjectScope: *b.HCloudScope, Physical: model.CapacityNativeWorkerHCloudPhysicalFacts{ResourceID: request.ResourceID, ProviderID: "hcloud://43210", Region: "hel1", NetworkZone: "eu-central"},
		RootStorage: model.CapacityNativeWorkerHCloudRootStorage{SizeGiB: 9007199254740993}, Reads: []model.CapacityNativeWorkerHCloudObservedRPC{{Operation: "GET /servers/{id}", HTTPStatus: 200, ObservedAt: time.Now().UTC()}}}
	raw, err := json.Marshal(o)
	if err != nil {
		t.Fatal(err)
	}
	got, err := nativePhysicalReadReply(b, request, "observed", json.RawMessage(raw))
	if err != nil || got.HCloud == nil || got.HCloud.RootStorage.SizeGiB != 9007199254740993 || got.HCloud.Physical.AccountID != "" || got.HCloud.Reads[0].RequestIDObserved {
		t.Fatal("HCloud wire was coerced to AWS account/HTTP identity or lost integer precision", err)
	}
	if got.Requested != (model.CapacityNativeWorkerObservationRequest{}) {
		t.Fatal("provider carrier populated the old AWS wire")
	}
	for name, bad := range map[string]string{
		"unknown":   strings.Replace(string(raw), "\"schema\":", "\"account_attested\":true,\"schema\":", 1),
		"duplicate": strings.Replace(string(raw), "\"binding_scope_sha256\":", "\"binding_scope_sha256\":\"wrong\",\"binding_scope_sha256\":", 1),
		"alias":     strings.Replace(string(raw), "\"project_scope\":", "\"ProjectScope\":", 1),
		"source":    strings.Replace(string(raw), b.SourceCommit, strings.Repeat("f", 40), 1),
		"scope":     strings.Replace(string(raw), b.ScopeSHA256, strings.Repeat("f", 64), 1),
		"version":   strings.Replace(string(raw), "\"version\":2", "\"version\":3", 1),
		"selector":  strings.Replace(string(raw), "\"resource_id\":\"43210\"", "\"resource_id\":\"43211\"", 1),
		"trailing":  string(raw) + "{}",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := nativePhysicalReadReply(b, request, "observed", json.RawMessage(bad)); err == nil {
				t.Fatal("ambiguous or rebound provider reply accepted")
			}
		})
	}
	if _, err := nativePhysicalReadReply(b, request, "succeeded", json.RawMessage(raw)); err == nil {
		t.Fatal("unobserved status accepted")
	}
	withoutScope := b
	withoutScope.HCloudScope = nil
	if _, err := nativePhysicalReadReply(withoutScope, request, "observed", json.RawMessage(raw)); err == nil {
		t.Fatal("HCloud without an actual reviewed project pin accepted")
	}
	aws := b
	aws.Provider, aws.HCloudScope = "aws", nil
	if _, err := nativePhysicalReadReply(aws, request, "observed", json.RawMessage(raw)); err == nil {
		t.Fatal("HCloud wire accepted through the original AWS decoder")
	}
}
