package model

import (
	"encoding/json"
	"testing"
)

func TestNativeWorkerPoolJSONRejectsAliasesNullsAndUnboundFields(t *testing.T) {
	for _, raw := range []string{
		`{"nodes":[{"Ready":true}]}`,
		`{"nodes":[{"ready":true,"ready":false}]}`,
		`{"nodes":[{"current_registration":null}]}`,
		`{"nodes":[{"systemd_active":true}]}`,
		`{"registry_ref":{"kind":"Lease","UID":"x"}}`,
		`{"owner_epoch":1,"owner_epoch":2}`,
		`{"nodes":null}`,
		`{"complete":true} false`,
	} {
		var o CapacityNativeWorkerPoolObservation
		if err := json.Unmarshal([]byte(raw), &o); err == nil {
			t.Fatalf("unsafe worker observation accepted: %s", raw)
		}
	}
	var o CapacityNativeWorkerPoolObservation
	if err := json.Unmarshal([]byte(`{"schema":"native_worker_pool_v1","owner_epoch":1,"nodes":[]}`), &o); err != nil || o.Nodes == nil {
		t.Fatalf("exact zero-node roster refused: %+v %v", o, err)
	}
	var b CapacityNativeWorkerPoolBinding
	if err := json.Unmarshal([]byte(`{"expected_pool_epoch":1,"registry_ref":{"kind":"Lease","namespace":"infra","name":"pool","uid":"a"},"profiles":[],"protected_nodes":[],"signals":[]}`), &b); err != nil {
		t.Fatal(err)
	}
}
