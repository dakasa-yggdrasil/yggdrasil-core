package integrationsurfaces

import (
	"encoding/json"
	"testing"
)

func TestManifestSpec_RoundTrip(t *testing.T) {
	raw := []byte(`{
		"category":"integration",
		"runtime":{"kind":"spa","base_path":"/s/slack","health_path":"/healthz"},
		"display":{"title":"Slack","appears_on":["ops-integrations","console-home"]},
		"core_contracts":["authorization","external_identity"],
		"capabilities":[{"name":"integration-admin","tabs":["overview","drift"]}]
	}`)
	var s ManifestSpec
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if s.Runtime.Kind != "spa" {
		t.Errorf("runtime.kind = %q", s.Runtime.Kind)
	}
	if got := len(s.Display.AppearsOn); got != 2 {
		t.Errorf("appears_on count = %d", got)
	}
}

func TestIsValidSlot(t *testing.T) {
	want := []string{"console-home", "ops-integrations", "me", "equipe", "orgchart", "colaborador-detail"}
	for _, s := range want {
		if !IsValidSlot(s) {
			t.Errorf("expected %q valid", s)
		}
	}
	if IsValidSlot("unknown") {
		t.Error("unknown should be invalid")
	}
}
