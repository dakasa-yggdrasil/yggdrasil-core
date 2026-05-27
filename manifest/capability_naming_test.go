package manifest

import (
	"path/filepath"
	"testing"
)

func TestLoadCapabilityNamingAllowlist_Exact(t *testing.T) {
	path := filepath.Join("..", "config", "capability_naming_allowlist.yaml")
	al, err := LoadCapabilityNamingAllowlist(path)
	if err != nil {
		t.Fatalf("LoadCapabilityNamingAllowlist failed: %v", err)
	}
	for _, want := range []string{"verify_webhook_signature", "publish_message", "create_refund"} {
		if !al.Allowed(want, "capability") {
			t.Errorf("expected %q to be allowed (exact match)", want)
		}
	}
}

func TestLoadCapabilityNamingAllowlist_Prefix(t *testing.T) {
	path := filepath.Join("..", "config", "capability_naming_allowlist.yaml")
	al, err := LoadCapabilityNamingAllowlist(path)
	if err != nil {
		t.Fatalf("LoadCapabilityNamingAllowlist failed: %v", err)
	}
	if !al.Allowed("calculate_iss", "capability") {
		t.Error("expected calculate_iss to be prefix-allowed")
	}
	if !al.Allowed("calculate_anything_else", "capability") {
		t.Error("expected calculate_* prefix to match any suffix")
	}
}

func TestLoadCapabilityNamingAllowlist_RejectsUnknown(t *testing.T) {
	path := filepath.Join("..", "config", "capability_naming_allowlist.yaml")
	al, err := LoadCapabilityNamingAllowlist(path)
	if err != nil {
		t.Fatalf("LoadCapabilityNamingAllowlist failed: %v", err)
	}
	if al.Allowed("create_user", "capability") {
		t.Error("expected create_user to NOT be allowed (must be ensure_user)")
	}
}

func TestLoadCapabilityNamingAllowlist_ReactorAlwaysAllowed(t *testing.T) {
	path := filepath.Join("..", "config", "capability_naming_allowlist.yaml")
	al, err := LoadCapabilityNamingAllowlist(path)
	if err != nil {
		t.Fatalf("LoadCapabilityNamingAllowlist failed: %v", err)
	}
	if !al.Allowed("zz_not_in_allowlist_at_all", "reactor") {
		t.Error("expected any name to be allowed when category=reactor")
	}
}
