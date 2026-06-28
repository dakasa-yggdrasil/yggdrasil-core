package integrationsurfaces

import (
	"encoding/json"
	"strings"
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

func TestManifestSpec_Queries_RoundTrip(t *testing.T) {
	raw := []byte(`{
		"category":"integration",
		"runtime":{"kind":"spa","base_path":"/s/employment-clt"},
		"display":{"title":"Pessoas"},
		"queries":[
			{"name":"list-employees","requires_permission":"clt:contract:view-all"},
			{"name":"my-employment"}
		]
	}`)
	var s ManifestSpec
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got := len(s.Queries); got != 2 {
		t.Fatalf("queries count = %d, want 2", got)
	}
	if s.Queries[0].Name != "list-employees" || s.Queries[0].RequiresPermission != "clt:contract:view-all" {
		t.Errorf("gated query = %+v", s.Queries[0])
	}
	// The self-service query carries no requires_permission ⇒ ungated.
	if s.Queries[1].RequiresPermission != "" {
		t.Errorf("my-employment must declare no permission, got %q", s.Queries[1].RequiresPermission)
	}

	// queries is omitempty: a spec without it emits no "queries" key, so existing
	// stored manifests round-trip byte-identically (no schema churn).
	out, err := json.Marshal(ManifestSpec{Category: "integration"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(out), "queries") {
		t.Errorf("empty queries must be omitted, got %s", out)
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
