package bootstrap

import (
	"encoding/json"
	"testing"

	manifestengine "github.com/dakasa-yggdrasil/yggdrasil-core/manifest"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// TestYggdrasilSelfSeedsValidate guards the embedded bootstrap seeds so a
// schema drift that would make ensureYggdrasilSelf fail at boot is caught in
// CI without a database. It also pins the canonical identity that the
// resolver join and every team_grant depend on.
func TestYggdrasilSelfSeedsValidate(t *testing.T) {
	cases := []struct {
		label   string
		payload []byte
		kind    string
	}{
		{"integration_type", yggdrasilSelfTypeSeed, "integration_type"},
		{"integration_instance", yggdrasilSelfInstanceSeed, "integration_instance"},
	}

	for _, tc := range cases {
		var doc model.ManifestDocument
		if err := json.Unmarshal(tc.payload, &doc); err != nil {
			t.Fatalf("%s: unmarshal: %v", tc.label, err)
		}
		doc = manifestengine.NormalizeDocument(doc)
		if err := manifestengine.ValidateDocument(doc); err != nil {
			t.Fatalf("%s: validate: %v", tc.label, err)
		}
		if doc.Kind != tc.kind {
			t.Fatalf("%s: expected kind %q, got %q", tc.label, tc.kind, doc.Kind)
		}
		if doc.Metadata.Namespace != YggdrasilSelfNamespace {
			t.Fatalf("%s: expected namespace %q, got %q", tc.label, YggdrasilSelfNamespace, doc.Metadata.Namespace)
		}
		if doc.Metadata.Name != YggdrasilSelfName {
			t.Fatalf("%s: expected name %q, got %q", tc.label, YggdrasilSelfName, doc.Metadata.Name)
		}
	}

	// The instance must reference the type by the same (namespace, name)
	// pair, or the resolver join can never match.
	var instance model.ManifestDocument
	if err := json.Unmarshal(yggdrasilSelfInstanceSeed, &instance); err != nil {
		t.Fatalf("unmarshal instance: %v", err)
	}
	var spec struct {
		TypeRef struct {
			Namespace string `json:"namespace"`
			Name      string `json:"name"`
		} `json:"type_ref"`
	}
	if err := json.Unmarshal(instance.Spec, &spec); err != nil {
		t.Fatalf("unmarshal instance spec: %v", err)
	}
	if spec.TypeRef.Namespace != YggdrasilSelfNamespace || spec.TypeRef.Name != YggdrasilSelfName {
		t.Fatalf("instance type_ref must be (%s,%s), got (%s,%s)",
			YggdrasilSelfNamespace, YggdrasilSelfName, spec.TypeRef.Namespace, spec.TypeRef.Name)
	}
}
