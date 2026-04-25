package manifest

import (
	"encoding/json"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func tenantFixture() model.TenantManifestSpec {
	return model.TenantManifestSpec{
		Slug:        "acme",
		DisplayName: "Acme Corp",
		Description: "Acme's multi-tenant scope on the platform",
		Owners:      []string{"team:platform", "user:alice"},
		BillingRef:  "stripe:cust_123",
	}
}

func TestValidateTenantSpec(t *testing.T) {
	if err := ValidateTenantSpec(tenantFixture()); err != nil {
		t.Fatalf("expected valid, got %v", err)
	}
}

func TestValidateTenantSpecRejectsBadSlug(t *testing.T) {
	for _, bad := range []string{"", "ACME", "a", "-acme", "acme-", "ac me"} {
		spec := tenantFixture()
		spec.Slug = bad
		if err := ValidateTenantSpec(spec); err == nil {
			t.Fatalf("expected error for slug %q", bad)
		}
	}
}

func TestValidateTenantSpecRejectsBadOwners(t *testing.T) {
	spec := tenantFixture()
	spec.Owners = []string{"alice"}
	if err := ValidateTenantSpec(spec); err == nil {
		t.Fatal("expected error for owner without prefix")
	}
	spec.Owners = []string{"random:abc"}
	if err := ValidateTenantSpec(spec); err == nil {
		t.Fatal("expected error for owner with unknown prefix")
	}
	spec.Owners = []string{""}
	if err := ValidateTenantSpec(spec); err == nil {
		t.Fatal("expected error for blank owner")
	}
}

func TestValidateTenantSpecRejectsNegativeQuotas(t *testing.T) {
	spec := tenantFixture()
	spec.Quotas = &model.TenantQuotas{MaxProjects: -1}
	if err := ValidateTenantSpec(spec); err == nil {
		t.Fatal("expected error for negative quota")
	}
}

func TestNormalizeTenantSpec(t *testing.T) {
	spec := model.TenantManifestSpec{Slug: "  ACME  ", DisplayName: " Acme "}
	out := NormalizeTenantSpec(spec)
	if out.Slug != "acme" {
		t.Fatalf("slug normalisation: got %q", out.Slug)
	}
	if out.DisplayName != "Acme" {
		t.Fatalf("display name normalisation: got %q", out.DisplayName)
	}
}

func TestTenantDocumentValidation(t *testing.T) {
	raw, err := json.Marshal(tenantFixture())
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	doc := model.ManifestDocument{
		APIVersion: "yggdrasil.io/v1alpha1",
		Kind:       "tenant",
		Metadata:   model.ManifestMetadataInput{Name: "acme", Namespace: "global"},
		Spec:       raw,
	}
	if err := ValidateDocument(doc); err != nil {
		t.Fatalf("ValidateDocument(tenant): %v", err)
	}
}
