package manifest

import (
	"encoding/json"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func TestValidateDocumentRBAC(t *testing.T) {
	doc := ManifestDocumentFixture()

	if err := ValidateDocument(doc); err != nil {
		t.Fatalf("ValidateDocument error: %v", err)
	}

	checksum, err := Checksum(doc)
	if err != nil {
		t.Fatalf("Checksum error: %v", err)
	}
	if checksum == "" {
		t.Fatal("expected checksum to be populated")
	}
}

func TestValidateDocumentRejectsUnknownRoleBinding(t *testing.T) {
	spec := model.RBACManifestSpec{
		Roles: []model.RBACRole{
			{
				Name: "viewer",
				Rules: []model.RBACRule{
					{Resources: []string{"manifest.*"}, Actions: []string{"read"}},
				},
			},
		},
		Bindings: []model.RBACBinding{
			{
				Name: "broken",
				Subjects: []model.RBACSubject{
					{Type: "collaborator", ID: "ana"},
				},
				Roles: []string{"admin"},
			},
		},
	}

	raw, err := json.Marshal(spec)
	if err != nil {
		t.Fatalf("json.Marshal error: %v", err)
	}

	doc := model.ManifestDocument{
		APIVersion: "yggdrasil.io/v1alpha1",
		Kind:       "rbac",
		Metadata: model.ManifestMetadataInput{
			Name:      "broken-rbac",
			Namespace: "global",
		},
		Spec: raw,
	}

	if err := ValidateDocument(doc); err == nil {
		t.Fatal("expected invalid binding reference to fail")
	}
}

func ManifestDocumentFixture() model.ManifestDocument {
	spec := model.RBACManifestSpec{
		Roles: []model.RBACRole{
			{
				Name: "viewer",
				Rules: []model.RBACRule{
					{Resources: []string{"manifest.*"}, Actions: []string{"read"}},
				},
			},
		},
		Bindings: []model.RBACBinding{
			{
				Name: "viewers",
				Subjects: []model.RBACSubject{
					{Type: "collaborator", ID: "ana"},
				},
				Roles: []string{"viewer"},
			},
		},
	}

	raw, _ := json.Marshal(spec)
	return model.ManifestDocument{
		APIVersion: "yggdrasil.io/v1alpha1",
		Kind:       "rbac",
		Metadata: model.ManifestMetadataInput{
			Name:      "global-rbac",
			Namespace: "global",
		},
		Spec: raw,
	}
}
