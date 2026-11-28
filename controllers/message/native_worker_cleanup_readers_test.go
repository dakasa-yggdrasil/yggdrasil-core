package message

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

func TestNativeCleanupPrivateReplyKeepsHistoricalOriginAndRejectsAliases(t *testing.T) {
	b := model.CapacityNativeWorkerPhysicalReadBinding{Profile: "aws", Provider: "aws", Adapter: model.CapacityMarketAdapterBinding{ManifestID: uuid.NewString(), Version: 7, Checksum: strings.Repeat("a", 64), IntegrationTypeID: uuid.NewString(), TypeChecksum: strings.Repeat("b", 64)}, BindingName: "cleanup-read", SourceCommit: strings.Repeat("c", 40), ScopeSHA256: strings.Repeat("d", 64)}
	f := &model.CapacityNativeWorkerResourceFootprint{Schema: "native_worker_resource_footprint_v1", EvidenceSHA256: strings.Repeat("e", 64)}
	req := model.CapacityNativeWorkerCleanupRequest{BindingName: b.BindingName, AttemptID: uuid.NewString(), ResourceID: "i-0123456789abcdef0", LaunchSHA256: strings.Repeat("f", 64), Footprint: f}
	o := model.CapacityNativeWorkerCleanupObservation{Schema: "native_worker_cleanup_observation_v1", Provider: "aws", Mode: "closure", SourceCommit: b.SourceCommit, Adapter: b.Adapter, BindingName: b.BindingName, BindingScopeSHA256: b.ScopeSHA256, Requested: model.CapacityNativeWorkerObservationRequest{BindingName: b.BindingName, AttemptID: req.AttemptID, ResourceID: req.ResourceID, LaunchSHA256: req.LaunchSHA256}, Footprint: f}
	raw, _ := json.Marshal(o)
	if _, err := nativeCleanupReadReply(b, req, "observed", json.RawMessage(raw)); err != nil {
		t.Fatal("exact historical selector reply refused", err)
	}
	for _, fault := range []string{"scope", "source", "version", "extra", "duplicate", "unicode", "history", "mode", "status"} {
		t.Run(fault, func(t *testing.T) {
			bad, status := string(raw), "observed"
			switch fault {
			case "scope":
				bad = strings.Replace(bad, b.ScopeSHA256, strings.Repeat("0", 64), 1)
			case "source":
				bad = strings.Replace(bad, b.SourceCommit, strings.Repeat("0", 40), 1)
			case "version":
				bad = strings.Replace(bad, `"version":7`, `"version":8`, 1)
			case "extra":
				bad = strings.TrimSuffix(bad, "}") + `,"mutation_authorized":true}`
			case "duplicate":
				bad = strings.Replace(bad, `"provider":"aws"`, `"provider":"aws","provider":"aws"`, 1)
			case "unicode":
				bad = strings.Replace(bad, `"resource_id"`, `"reſource_id"`, 1)
			case "history":
				bad = strings.Replace(bad, f.EvidenceSHA256, strings.Repeat("0", 64), 1)
			case "mode":
				bad = strings.Replace(bad, `"mode":"closure"`, `"mode":"snapshot"`, 1)
			case "status":
				status = "succeeded"
			}
			if _, err := nativeCleanupReadReply(b, req, status, json.RawMessage(bad)); err == nil {
				t.Fatal("unbound or ambiguous cleanup reply accepted", fault)
			}
		})
	}
	if _, err := NewProtectedNativeWorkerCleanupReadFunc(nil, nil, nil)(t.Context(), b, req); err == nil {
		t.Fatal("uninstalled callback acquired reader authority")
	}
	if _, err := NewProtectedNativeWorkerAbortInventoryReadFunc(nil, nil, nil)(t.Context(), model.CapacityNativeWorkerPhaseReadBinding{}, model.CapacityNativeWorkerAbortInventoryRequest{}); err == nil {
		t.Fatal("uninstalled inventory acquired reader authority")
	}
	if _, err := NewProtectedNativeWorkerConcreteAbortRuntime(nil, nil, model.Manifest{}, nil, nil, nil); err == nil {
		t.Fatal("uninstalled composition accepted")
	}
}
